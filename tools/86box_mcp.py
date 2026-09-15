#!/usr/bin/env python3
"""Expose RetroOS's COM2 diagnostic-control service as local MCP tools.

RetroOS owns the commands and executes them in its kernel. This process only
adapts Codex's STDIO MCP transport to 86Box's bidirectional COM pipe.
"""

from __future__ import annotations

import argparse
import errno
import json
import os
import select
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


def candidate_bases(explicit: str | None) -> list[Path]:
    if explicit:
        return [Path(explicit).expanduser()]
    configured = os.environ.get("RETROOS_MCP_SERIAL")
    if configured:
        return [Path(configured).expanduser()]
    home = Path.home()
    discovered_outputs = [
        *home.glob(".var/app/*/data/86Box/RetroOS/mcp-serial.out"),
        *Path("/tmp").glob("retroos-*/mcp-serial.out"),
    ]
    candidates = [
        home / ".local/share/86Box/RetroOS/mcp-serial",
        *(Path(str(output)[:-4]) for output in discovered_outputs),
    ]
    return sorted(
        candidates,
        key=lambda path: Path(str(path) + ".out").stat().st_mtime
        if Path(str(path) + ".out").exists() else 0,
        reverse=True,
    )


class SerialControl:
    def __init__(self, explicit: str | None):
        self.explicit = explicit
        self.reader: int | None = None
        self.writer: int | None = None
        self.pending = bytearray()
        self.synced = False

    def close(self) -> None:
        for descriptor in (self.reader, self.writer):
            if descriptor is not None:
                os.close(descriptor)
        self.reader = None
        self.writer = None
        self.pending.clear()
        self.synced = False

    def connect(self, deadline: float) -> None:
        if self.reader is not None and self.writer is not None:
            return
        last_error = "no mcp-serial.in/.out pair found"
        while time.monotonic() < deadline:
            for base in candidate_bases(self.explicit):
                incoming = Path(str(base) + ".out")
                outgoing = Path(str(base) + ".in")
                if not incoming.exists() or not outgoing.exists():
                    continue
                reader: int | None = None
                try:
                    reader = os.open(incoming, os.O_RDONLY | os.O_NONBLOCK)
                    writer = os.open(outgoing, os.O_WRONLY | os.O_NONBLOCK)
                except OSError as error:
                    if reader is not None:
                        os.close(reader)
                    last_error = str(error)
                    if error.errno not in (errno.ENXIO, errno.ENOENT):
                        raise
                    continue
                self.reader = reader
                self.writer = writer
                # A newly attached 86Box pipe reports a transient readable EOF
                # while its UART endpoint reconnects.
                time.sleep(0.05)
                return
            time.sleep(0.05)
        raise RuntimeError(last_error)

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
                os.write(self.writer, bytes((byte,)))
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
                chunk = os.read(self.reader, 4096)
                if chunk:
                    self.pending.extend(chunk)
                else:
                    time.sleep(0.01)
            raise RuntimeError(f"RetroOS did not reply to {command!r}")
        except (OSError, json.JSONDecodeError):
            self.close()
            raise


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


def serve(pipe: str | None) -> None:
    serial = SerialControl(pipe)
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
                    "instructions": "These tools execute directly in the RetroOS kernel over COM2. Use profile_reads for reliable structured DOS read timings; profile_dump also writes the complete report to COM1.",
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
    serve(parser.parse_args().pipe)


if __name__ == "__main__":
    main()
