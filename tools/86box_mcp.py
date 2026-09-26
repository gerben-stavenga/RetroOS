#!/usr/bin/env python3
"""Expose RetroOS's COM2 diagnostic-control service as local MCP tools.

RetroOS owns the commands and executes them in its kernel. This process only
adapts a stdio MCP session to the host serial endpoint: an 86Box named-pipe
pair, or the unix socket QEMU attaches to COM2.
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
    if name == "profile_set":
        return ["profile on" if arguments.get("enabled") is True else "profile off"]
    if name == "profile_reset": return ["profile reset"]
    if name == "profile_dump": return ["profile dump"]
    if name == "profile_reads": return ["profile reads"]
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


def serve(pipe: str | None, sock: str | None) -> None:
    serial = SerialControl(pipe, sock)
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
                    "instructions": "These tools execute directly in the RetroOS kernel over COM2, via an 86Box named pipe or the QEMU socket printed as 'MCP control'. Use profile_reads for reliable structured DOS read timings; profile_dump also writes the complete report to the kernel log.",
                })
            elif method == "ping": emit(identifier, {})
            elif method == "tools/list": emit(identifier, {"tools": TOOLS})
            elif method == "tools/call":
                params = request.get("params") or {}
                try:
                    commands = commands_for(str(params.get("name", "")), params.get("arguments") or {})
                    replies = [serial.request(command) for command in commands]
                    result: Any = replies[0] if len(replies) == 1 else replies
                    failed = any(not reply.get("ok", False) for reply in replies)
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
    parser.add_argument("--pipe", help="86Box COM pipe base (without .in/.out)")
    parser.add_argument("--socket", help="QEMU COM2 unix socket (run.sh prints this path)")
    args = parser.parse_args()
    if args.pipe and args.socket:
        parser.error("pass only one of --pipe and --socket")
    serve(args.pipe, args.socket)


if __name__ == "__main__":
    main()
