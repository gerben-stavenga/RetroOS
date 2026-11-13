#!/usr/bin/env python3
"""Expose RetroOS diagnostic control as local MCP tools.

RetroOS owns the commands and executes them in its kernel. This process only
adapts a stdio MCP session to the host serial endpoint: an 86Box named-pipe
pair, the unix socket QEMU attaches to COM2, or /dev/retroos-control
when running inside RetroOS itself.
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import select
import socket
import stat
import sys
import time
from pathlib import Path
from typing import Any


TOOLS = [
    {
        "name": "profile_workers",
        "description": "Per-worker syscall and nested I/O timings for the current profile window. CPU times overlap each other and BSP wall time; do not add them to profile_totals.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "parallel_status",
        "description": "Return eligible CPUs and per-worker syscall counts, handler nanoseconds and kernel-service lock wait since boot. These worker CPU counters are separate from the BSP wall-time ledger; CPU 0 is excluded.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "profile_begin",
        "description": "Start a fresh whole-system capture on the event-loop CPU: reset every counter and begin recording. Run the workload immediately, then call profile_end. Concurrent processes and MCP bracketing are included.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "profile_end",
        "description": "Stop recording at the current boundary and return one frozen, rubriced profile: disjoint nanosecond ledger, syscall names/counts/total/average/max, nested I/O, directory cache hits/rebuilds/invalidations, and reconciliation checks. Check quality.valid before trusting derived totals.",
        "inputSchema": {"type": "object", "properties": {"include_raw": {"type": "boolean", "default": False, "description": "Also include original counters for independent auditing."}}, "additionalProperties": False},
    },
    {
        "name": "profile_report",
        "description": "Read the same frozen capture without changing counters. Requires recording stopped; use profile_end first. Nested I/O must not be added to the disjoint execution ledger.",
        "inputSchema": {"type": "object", "properties": {"include_raw": {"type": "boolean", "default": False, "description": "Also include original counters for independent auditing."}}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "profile_set",
        "description": "Enable or disable RetroOS kernel cycle profiling directly.",
        "inputSchema": {
            "type": "object",
            "properties": {"enabled": {"type": "boolean"}},
            "required": ["enabled"],
            "additionalProperties": False,
        },
    },
    {
        "name": "profile_reset",
        "description": "Reset RetroOS kernel, OSD, and event profile counters without changing enable state.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "profile_dump",
        "description": "Dump the complete profile to COM1 and return the current coarse profile state.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "profile_reads",
        "description": "Return per-request-size DOS file-read cycle counters over the reliable control channel.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "profile_syscalls",
        "description": "Return every Linux syscall's ABI, number, count, total handler nanoseconds and maximum; excludes blocked waiting and outer-loop work.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True},
    },
    *[{
        "name": "profile_" + name,
        "description": description,
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True},
    } for name, description in (
        ("io", "Return nested filesystem, cache, device and outer-loop timings; do not add overlapping stages."),
        ("heap", "Return kernel heap allocation counters."),
        ("totals", "Return the disjoint BSP wall-time ledger and profile duration. Parallel worker CPU time is excluded; BSP preparation and rendezvous are scheduler work."),
    )],
    {
        "name": "profile_top",
        "description": "Return the 32 busiest profiled guest-exit classes over the reliable control channel.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "profile_rm_calls",
        "description": "Return profiled DPMI real-mode call targets and call counts.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "profile_execution",
        "description": "Return exact cycle totals for policy, register bridge, ring-0 entry/exit, guest execution, and event decoding.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "trace_set",
        "description": "Enable or disable RetroOS syscall tracing directly.",
        "inputSchema": {
            "type": "object",
            "properties": {"enabled": {"type": "boolean"}},
            "required": ["enabled"],
            "additionalProperties": False,
        },
    },
    {
        "name": "diagnostics_status",
        "description": "Read RetroOS profile/trace state and coarse cycle counters.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "debug_dump",
        "description": "Dump the running guest's register and virtual-hardware state directly to COM1.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "send_keys",
        "description": "Inject named keyboard taps through RetroOS's normal input router.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "keys": {
                    "type": "array",
                    "items": {"type": "string", "enum": [
                        "ESC", "BACKSPACE", "TAB", "ENTER", "SPACE",
                        "UP", "DOWN", "LEFT", "RIGHT", "HOME", "END",
                        "PGUP", "PGDN", "INSERT", "DELETE",
                        "F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8",
                        "F9", "F10", "F11", "F12"
                    ]},
                    "minItems": 1,
                    "maxItems": 32,
                },
            },
            "required": ["keys"],
            "additionalProperties": False,
        },
    },
    {
        "name": "type_text",
        "description": "Inject printable US-ASCII text through RetroOS's normal input router; use send_keys for Enter.",
        "inputSchema": {
            "type": "object",
            "properties": {"text": {"type": "string", "minLength": 1, "maxLength": 100}},
            "required": ["text"],
            "additionalProperties": False,
        },
    },
]


def is_socket(path: Path) -> bool:
    if path.suffix == ".sock":
        return True
    try:
        return stat.S_ISSOCK(path.stat().st_mode)
    except OSError:
        return False


def discover_endpoints(pipe: str | None, sock: str | None) -> list[tuple[str, Path]]:
    """Newest live endpoint first. An explicit path is the only candidate."""
    if sock:
        return [("socket", Path(sock).expanduser())]
    if pipe:
        return [("pipe", Path(pipe).expanduser())]
    configured = os.environ.get("RETROOS_MCP_SERIAL")
    if configured:
        path = Path(configured).expanduser()
        return [("socket" if is_socket(path) else "pipe", path)]
    found: list[tuple[float, str, Path]] = []
    for path in Path("/tmp").glob("retroos-run.*/mcp.sock"):
        try:
            found.append((path.stat().st_mtime, "socket", path))
        except OSError:
            continue
    home = Path.home()
    pipe_bases = [
        home / ".local/share/86Box/RetroOS/mcp-serial",
        *(Path(str(output)[:-4]) for output in home.glob(".var/app/*/data/86Box/RetroOS/mcp-serial.out")),
        *(Path(str(output)[:-4]) for output in Path("/tmp").glob("retroos-*/mcp-serial.out")),
    ]
    seen: set[Path] = set()
    for base in pipe_bases:
        if base in seen:
            continue
        seen.add(base)
        outgoing = Path(str(base) + ".out")
        try:
            found.append((outgoing.stat().st_mtime, "pipe", base))
        except OSError:
            continue
    found.sort(key=lambda item: item[0], reverse=True)
    return [(kind, path) for _, kind, path in found]


class LocalControl:
    """A per-open kernel command stream; actions are never automatically replayed."""

    def __init__(self, path: str = "/dev/retroos-control"):
        self.path = path
        self.fd: int | None = None

    def close(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def request(self, command: str, timeout: float = 8.0) -> dict[str, Any]:
        payload = command.encode("ascii") + b"\n"
        if len(payload) > 256 or b"\n" in payload[:-1]:
            raise ValueError("expected one command of at most 255 ASCII bytes")
        if self.fd is None:
            self.fd = os.open(self.path, os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC)
        deadline = time.monotonic() + timeout
        try:
            count = os.write(self.fd, payload)
            if count != len(payload):
                raise RuntimeError("short local control write")
            reply = bytearray()
            while time.monotonic() < deadline:
                try:
                    chunk = os.read(self.fd, 4096)
                except BlockingIOError:
                    time.sleep(.005)
                    continue
                if not chunk:
                    raise RuntimeError("local control stream closed")
                reply.extend(chunk)
                if len(reply) > 256 * 1024:
                    raise RuntimeError("local control reply too large")
                if reply.endswith(b"\n"):
                    return json.loads(reply)
            raise RuntimeError("local control request timed out")
        except Exception:
            self.close()
            raise


def control_for(pipe: str | None, sock: str | None, device: str | None = None):
    if device is not None:
        return LocalControl(device)
    if pipe is None and sock is None and Path("/dev/retroos-control").is_char_device():
        return LocalControl()
    return SerialControl(pipe, sock)


class SerialControl:
    def __init__(self, pipe: str | None, sock: str | None):
        self.pipe = pipe
        self.sock = sock
        self.reader: int | None = None
        self.writer: int | None = None
        self.pending = bytearray()
        self.synced = False

    def close(self) -> None:
        closed: set[int] = set()
        for descriptor in (self.reader, self.writer):
            if descriptor is not None and descriptor not in closed:
                os.close(descriptor)
                closed.add(descriptor)
        self.reader = None
        self.writer = None
        self.pending.clear()
        self.synced = False

    def connect(self, deadline: float) -> None:
        if self.reader is not None and self.writer is not None:
            return
        last_error = "no QEMU mcp.sock or 86Box mcp-serial.in/.out pair found"
        while time.monotonic() < deadline:
            endpoints = discover_endpoints(self.pipe, self.sock)
            if not endpoints:
                last_error = "no QEMU mcp.sock or 86Box mcp-serial.in/.out pair found"
            for kind, path in endpoints:
                try:
                    if kind == "socket":
                        self._connect_socket(path)
                    else:
                        self._connect_pipe(path)
                    return
                except OSError as error:
                    self.close()
                    last_error = str(error)
                    if error.errno not in (
                        errno.ENXIO, errno.ENOENT, errno.ECONNREFUSED, errno.EAGAIN, errno.EWOULDBLOCK,
                    ):
                        raise
            time.sleep(0.05)
        raise RuntimeError(last_error)

    def _connect_socket(self, path: Path) -> None:
        endpoint = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            endpoint.connect(os.fspath(path))
            endpoint.setblocking(False)
            descriptor = endpoint.detach()
        except OSError:
            endpoint.close()
            raise
        self.reader = descriptor
        self.writer = descriptor

    def _connect_pipe(self, base: Path) -> None:
        incoming = Path(str(base) + ".out")
        outgoing = Path(str(base) + ".in")
        if not incoming.exists() or not outgoing.exists():
            raise FileNotFoundError(errno.ENOENT, "mcp-serial pipe is not present", str(base))
        reader: int | None = None
        try:
            reader = os.open(incoming, os.O_RDONLY | os.O_NONBLOCK)
            writer = os.open(outgoing, os.O_WRONLY | os.O_NONBLOCK)
        except OSError:
            if reader is not None:
                os.close(reader)
            raise
        self.reader = reader
        self.writer = writer
        # A newly attached 86Box pipe reports a transient readable EOF
        # while its UART endpoint reconnects.
        time.sleep(0.05)

    def request(self, command: str, timeout: float = 8.0) -> dict[str, Any]:
        final_deadline = time.monotonic() + timeout
        # 86Box's first reply can race its Named Pipe reconnect. Synchronize
        # with a read-only status request, so a retry can never duplicate the
        # requested action (notably a full debug dump).
        while not self.synced and time.monotonic() < final_deadline:
            try:
                probe_deadline = min(final_deadline, time.monotonic() + 1.0)
                self._request_once("status", probe_deadline)
                self.synced = True
            except RuntimeError:
                # 86Box's reconnecting pipe needs time to observe the first
                # client disconnect before the reply side becomes usable.
                self.close()
                time.sleep(0.25)
        if not self.synced:
            raise RuntimeError("RetroOS serial control did not synchronize")
        return self._request_once(command, final_deadline)

    def _request_once(self, command: str, deadline: float) -> dict[str, Any]:
        self.connect(deadline)
        if self.writer is None or self.reader is None:
            raise RuntimeError("serial control connection disappeared")
        payload = command.encode("ascii") + b"\n"
        try:
            # A slow emulated CPU may service its 16-byte UART FIFO much less
            # often than wall-clock baud timing suggests. Pace individual
            # bytes so long commands cannot overrun it.
            for byte in payload:
                self._write_byte(byte, deadline)
                time.sleep(0.001)
            while time.monotonic() < deadline:
                newline = self.pending.find(b"\n")
                if newline >= 0:
                    line = bytes(self.pending[:newline])
                    del self.pending[:newline + 1]
                    return json.loads(line)
                remaining = max(0.0, deadline - time.monotonic())
                ready, _, _ = select.select([self.reader], [], [], min(0.1, remaining))
                if not ready:
                    continue
                try:
                    chunk = os.read(self.reader, 4096)
                except BlockingIOError:
                    continue
                if chunk:
                    self.pending.extend(chunk)
                else:
                    time.sleep(0.01)
            raise RuntimeError(f"RetroOS did not reply to {command!r}")
        except (OSError, json.JSONDecodeError):
            self.close()
            raise

    def _write_byte(self, byte: int, deadline: float) -> None:
        if self.writer is None:
            raise RuntimeError("serial control connection disappeared")
        data = bytes((byte,))
        while True:
            try:
                written = os.write(self.writer, data)
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("serial control write timed out") from None
                select.select([], [self.writer], [], 0.05)
                continue
            if written == 1:
                return
            raise OSError("serial control write made no progress")


def text_content(value: Any) -> list[dict[str, Any]]:
    return [{"type": "text", "text": json.dumps(value, sort_keys=True)}]


def commands_for(name: str, arguments: dict[str, Any]) -> list[str]:
    if name == "profile_workers": return ["profile workers"]
    if name == "parallel_status": return ["parallel status"]
    if name == "profile_begin": return ["profile begin"]
    if name == "profile_end": return ["profile end"]
    if name == "profile_report": return ["profile report"]
    if name == "profile_set":
        return ["profile on" if arguments.get("enabled") is True else "profile off"]
    if name == "profile_reset": return ["profile reset"]
    if name == "profile_dump": return ["profile dump"]
    if name == "profile_reads": return ["profile reads"]
    if name == "profile_syscalls": return ["profile syscalls"]
    if name == "profile_io": return ["profile io"]
    if name == "profile_heap": return ["profile heap"]
    if name == "profile_totals": return ["profile totals"]
    if name == "profile_top": return ["profile top"]
    if name == "profile_rm_calls": return ["profile rm"]
    if name == "profile_execution": return ["profile execution"]
    if name == "trace_set":
        return ["trace on" if arguments.get("enabled") is True else "trace off"]
    if name == "diagnostics_status": return ["status"]
    if name == "debug_dump": return ["debug dump"]
    if name == "send_keys":
        keys = arguments.get("keys")
        if not isinstance(keys, list) or not keys or not all(isinstance(key, str) for key in keys):
            raise ValueError("keys must be a non-empty string array")
        return [f"key {key}" for key in keys]
    if name == "type_text":
        text = arguments.get("text")
        if not isinstance(text, str) or not text or len(text) > 100:
            raise ValueError("text must contain 1..100 characters")
        if any(ord(char) < 0x20 or ord(char) > 0x7E for char in text):
            raise ValueError("text must be printable US-ASCII; inject Enter with send_keys")
        return [f"texthex {text.encode('ascii').hex()}"]
    raise ValueError(f"unknown tool: {name}")


def emit(identifier: Any, result: Any = None, error: dict[str, Any] | None = None) -> None:
    message: dict[str, Any] = {"jsonrpc": "2.0", "id": identifier}
    message["error" if error is not None else "result"] = error if error is not None else result
    sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def serve(pipe: str | None, sock: str | None, device: str | None = None) -> None:
    serial = control_for(pipe, sock, device)
    for raw_line in sys.stdin.buffer:
        try:
            request = json.loads(raw_line)
            identifier = request.get("id")
            if identifier is None:
                continue
            method = request.get("method")
            if method == "initialize":
                emit(identifier, {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "retroos-serial", "version": "1.0.0"},
                    "instructions": "These tools execute in the RetroOS kernel. Inside RetroOS the bridge automatically uses /dev/retroos-control; outside it uses the QEMU COM2 socket or 86Box pipe. profile_totals is a disjoint BSP wall-time ledger that excludes worker CPU time; profile_io stages overlap and must not be added together. profile_dump also writes to the kernel log.",
                })
            elif method == "ping": emit(identifier, {})
            elif method == "tools/list": emit(identifier, {"tools": TOOLS})
            elif method == "tools/call":
                params = request.get("params") or {}
                try:
                    commands = commands_for(str(params.get("name", "")), params.get("arguments") or {})
                    replies = [serial.request(command, timeout=60.0 if command in ("profile end", "profile report") else 8.0) for command in commands]
                    if params.get("name") in ("profile_end", "profile_report"):
                        from profile_report import make_report
                        replies = [make_report(reply) for reply in replies]
                        if not (params.get("arguments") or {}).get("include_raw", False):
                            for reply in replies:
                                reply.pop("raw", None)
                    result: Any = replies[0] if len(replies) == 1 else replies
                    failed = any(not reply.get("ok", False) or not reply.get("quality", {}).get("valid", True) for reply in replies)
                    emit(identifier, {"content": text_content(result), "isError": failed})
                except Exception as error:
                    emit(identifier, {"content": [{"type": "text", "text": str(error)}], "isError": True})
            else:
                emit(identifier, error={"code": -32601, "message": f"method not found: {method}"})
        except (json.JSONDecodeError, TypeError, ValueError) as error:
            emit(None, error={"code": -32700, "message": str(error)})
    serial.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    endpoint = parser.add_mutually_exclusive_group()
    endpoint.add_argument("--pipe", help="86Box COM pipe base (without .in/.out)")
    endpoint.add_argument("--socket", help="QEMU COM2 unix socket (run.sh prints this path)")
    endpoint.add_argument("--device", help="Local RetroOS kernel control device (auto-detected by default)")
    args = parser.parse_args()
    serve(args.pipe, args.socket, args.device)


if __name__ == "__main__":
    main()
