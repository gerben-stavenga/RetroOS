#!/usr/bin/env python3
"""Drive a running 86Box VM and inspect its diagnostic log.

This is deliberately separate from run.sh: a diagnostic VM can be launched by
run.sh (including Flatpak sandbox setup), while this tool can be invoked many
times to drive it without restarting it.

Examples:
  tools/86box_driver.py wait --title RetroOS-DarkDiag
  tools/86box_driver.py type --title RetroOS-DarkDiag 'c:\\games\\dforces\\dark.exe'
  tools/86box_driver.py key --title RetroOS-DarkDiag ENTER
  tools/86box_driver.py key --title RetroOS-DarkDiag F12 TAB RIGHT ENTER
  tools/86box_driver.py click --title RetroOS-DarkDiag 91 38
  tools/86box_driver.py screenshot --title RetroOS-DarkDiag /tmp/dark.png
  tools/86box_driver.py capture --kernel-log --log /tmp/dark.log -- ./run.sh 86box
  tools/86box_driver.py log --lines 80 --follow /tmp/dark.log

DISPLAY selects the X server (normally inherited as :1). The title is a
substring of the VM name shown by 86Box. If it matches more than one live VM,
the command fails instead of sending input to the wrong guest.
"""

from __future__ import annotations

import argparse
import ctypes
import os
import re
import signal
import shutil
import subprocess
import threading
import time
from pathlib import Path


# The emulator's WM class. 86Box by default, but the same XTest driving works
# on any emulator window — Bochs' SDL window, for one, which is where an OSD
# bug specific to its VBE linear scanout has to be reproduced.
WINDOW_CLASS = "86Box"


def window_re() -> re.Pattern[str]:
    return re.compile(
        r'^\s*(0x[0-9a-fA-F]+)\s+"([^"]*)":\s+\("[^"]*"\s+"'
        + re.escape(WINDOW_CLASS) + r'"\)'
    )
KERNEL_LOG_RE = re.compile(r"^86box: RetroOS kernel log file: (.+)\s*$")


def windows() -> list[tuple[int, str]]:
    try:
        text = subprocess.check_output(
            ["xwininfo", "-root", "-tree"], text=True, stderr=subprocess.DEVNULL
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(f"cannot query X11 windows: {error}") from error
    found: list[tuple[int, str]] = []
    pattern = window_re()
    for line in text.splitlines():
        match = pattern.match(line)
        if match:
            found.append((int(match.group(1), 16), match.group(2)))
    return found


def select_window(title: str) -> tuple[int, str]:
    matches = [(wid, name) for wid, name in windows() if title.casefold() in name.casefold()]
    if not matches:
        raise SystemExit(f"no 86Box window matches {title!r}")
    if len(matches) != 1:
        names = "\n".join(f"  {wid:#x}  {name}" for wid, name in matches)
        raise SystemExit(f"multiple 86Box windows match {title!r}:\n{names}")
    return matches[0]


class XTest:
    SHIFT = 0xFFE1

    def __init__(self, window: int):
        self.x11 = ctypes.CDLL("libX11.so.6")
        self.xtst = ctypes.CDLL("libXtst.so.6")
        self.x11.XOpenDisplay.argtypes = [ctypes.c_char_p]
        self.x11.XOpenDisplay.restype = ctypes.c_void_p
        self.x11.XStringToKeysym.argtypes = [ctypes.c_char_p]
        self.x11.XStringToKeysym.restype = ctypes.c_ulong
        self.x11.XKeysymToKeycode.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        self.x11.XKeysymToKeycode.restype = ctypes.c_uint
        self.x11.XSetInputFocus.argtypes = [
            ctypes.c_void_p, ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong
        ]
        self.x11.XGetInputFocus.argtypes = [
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong), ctypes.POINTER(ctypes.c_int)
        ]
        self.x11.XRaiseWindow.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        self.x11.XWarpPointer.argtypes = [
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_uint,
            ctypes.c_uint,
            ctypes.c_int,
            ctypes.c_int,
        ]
        self.x11.XFlush.argtypes = [ctypes.c_void_p]
        self.x11.XCloseDisplay.argtypes = [ctypes.c_void_p]
        self.xtst.XTestFakeKeyEvent.argtypes = [
            ctypes.c_void_p, ctypes.c_uint, ctypes.c_int, ctypes.c_ulong
        ]
        self.xtst.XTestFakeButtonEvent.argtypes = [
            ctypes.c_void_p, ctypes.c_uint, ctypes.c_int, ctypes.c_ulong
        ]
        self.display = self.x11.XOpenDisplay(None)
        if not self.display:
            raise SystemExit(f"cannot open DISPLAY={os.environ.get('DISPLAY', '')!r}")
        self.window = window
        previous = ctypes.c_ulong()
        revert = ctypes.c_int()
        self.x11.XGetInputFocus(self.display, ctypes.byref(previous), ctypes.byref(revert))
        self.previous_focus = previous.value
        self.previous_revert = revert.value
        self.x11.XSetInputFocus(self.display, window, 2, 0)  # RevertToParent, CurrentTime
        self.x11.XFlush(self.display)

    def close(self) -> None:
        if self.previous_focus:
            self.x11.XSetInputFocus(
                self.display, self.previous_focus, self.previous_revert, 0
            )
            self.x11.XFlush(self.display)
        self.x11.XCloseDisplay(self.display)

    def keysym(self, name: str) -> int:
        value = self.x11.XStringToKeysym(name.encode("ascii"))
        if not value:
            raise SystemExit(f"unknown X11 key name: {name}")
        return value

    def tap(self, keysym: int, shifted: bool = False) -> None:
        keycode = self.x11.XKeysymToKeycode(self.display, keysym)
        shift_code = self.x11.XKeysymToKeycode(self.display, self.SHIFT)
        if not keycode:
            raise SystemExit(f"X11 has no keycode for keysym {keysym:#x}")
        if shifted:
            self.xtst.XTestFakeKeyEvent(self.display, shift_code, True, 0)
        self.xtst.XTestFakeKeyEvent(self.display, keycode, True, 0)
        self.x11.XFlush(self.display)
        time.sleep(0.02)
        self.xtst.XTestFakeKeyEvent(self.display, keycode, False, 0)
        if shifted:
            self.xtst.XTestFakeKeyEvent(self.display, shift_code, False, 0)
        self.x11.XFlush(self.display)
        time.sleep(0.02)

    def named(self, name: str) -> None:
        aliases = {
            "ENTER": "Return",
            "ESC": "Escape",
            "BACKSPACE": "BackSpace",
            "TAB": "Tab",
            "UP": "Up",
            "DOWN": "Down",
            "LEFT": "Left",
            "RIGHT": "Right",
        }
        self.tap(self.keysym(aliases.get(name.upper(), name)))

    def text(self, value: str) -> None:
        shifted = {
            "~": "`", "!": "1", "@": "2", "#": "3", "$": "4", "%": "5",
            "^": "6", "&": "7", "*": "8", "(": "9", ")": "0", "_": "-",
            "+": "=", "{": "[", "}": "]", "|": "\\", ":": ";", '"': "'",
            "<": ",", ">": ".", "?": "/",
        }
        for char in value:
            if char in shifted:
                self.tap(ord(shifted[char]), True)
            elif "A" <= char <= "Z":
                self.tap(ord(char.lower()), True)
            elif 0x20 <= ord(char) <= 0x7E:
                self.tap(ord(char))
            else:
                raise SystemExit(f"cannot type non-ASCII character {char!r}")

    def click(self, x: int, y: int, button: int = 1) -> None:
        self.x11.XWarpPointer(self.display, 0, self.window, 0, 0, 0, 0, x, y)
        self.x11.XFlush(self.display)
        time.sleep(0.02)
        self.xtst.XTestFakeButtonEvent(self.display, button, True, 0)
        self.x11.XFlush(self.display)
        time.sleep(0.02)
        self.xtst.XTestFakeButtonEvent(self.display, button, False, 0)
        self.x11.XFlush(self.display)
        time.sleep(0.02)

    def raise_window(self) -> None:
        self.x11.XRaiseWindow(self.display, self.window)
        self.x11.XFlush(self.display)


def command_wait(args: argparse.Namespace) -> None:
    deadline = time.monotonic() + args.timeout
    while True:
        matches = [(wid, name) for wid, name in windows() if args.title.casefold() in name.casefold()]
        if len(matches) == 1:
            print(f"{matches[0][0]:#x} {matches[0][1]}")
            return
        if len(matches) > 1:
            select_window(args.title)
        if time.monotonic() >= deadline:
            raise SystemExit(f"timed out waiting for 86Box window matching {args.title!r}")
        time.sleep(0.25)


def command_key(args: argparse.Namespace) -> None:
    wid, _ = select_window(args.title)
    driver = XTest(wid)
    try:
        for name in args.keys:
            driver.named(name)
    finally:
        driver.close()


def command_type(args: argparse.Namespace) -> None:
    wid, _ = select_window(args.title)
    driver = XTest(wid)
    try:
        driver.text(args.text)
    finally:
        driver.close()


def command_click(args: argparse.Namespace) -> None:
    wid, _ = select_window(args.title)
    driver = XTest(wid)
    try:
        driver.click(args.x, args.y, args.button)
    finally:
        driver.close()


def command_raise(args: argparse.Namespace) -> None:
    wid, _ = select_window(args.title)
    driver = XTest(wid)
    try:
        driver.raise_window()
    finally:
        driver.close()


def command_screenshot(args: argparse.Namespace) -> None:
    wid, _ = select_window(args.title)
    for command in ("xwd", "ffmpeg"):
        if not shutil.which(command):
            raise SystemExit(f"{command} is required for screenshots")
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    xwd = subprocess.Popen(
        ["xwd", "-silent", "-id", f"{wid:#x}"], stdout=subprocess.PIPE
    )
    converted = subprocess.run(
        ["ffmpeg", "-loglevel", "error", "-y", "-i", "pipe:0", "-frames:v", "1", str(output)],
        stdin=xwd.stdout,
    )
    if xwd.stdout is not None:
        xwd.stdout.close()
    xwd_status = xwd.wait()
    if xwd_status or converted.returncode:
        raise SystemExit("screenshot capture failed")
    print(output)


def command_log(args: argparse.Namespace) -> None:
    path = Path(args.path)
    while not path.exists():
        if not args.follow:
            raise SystemExit(f"log does not exist: {path}")
        time.sleep(0.25)
    with path.open("r", errors="replace") as stream:
        data = stream.readlines()
        first = max(0, len(data) - args.lines)
        for index, line in enumerate(data[first:], first + 1):
            print(f"{index:06d} {line}", end="")
        if not args.follow:
            return
        position = stream.tell()
        index = len(data)
        while True:
            stream.seek(position)
            line = stream.readline()
            if line:
                position = stream.tell()
                index += 1
                print(f"{index:06d} {line}", end="", flush=True)
            else:
                time.sleep(0.1)


def command_capture(args: argparse.Namespace) -> None:
    command = args.program
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        raise SystemExit("capture needs a command after --")
    path = Path(args.log)
    path.parent.mkdir(parents=True, exist_ok=True)
    environment = os.environ.copy()
    if args.kernel_log:
        environment["RETROOS_86BOX_KERNEL_LOG"] = "1"
    with path.open("w") as output:
        lock = threading.Lock()
        line_number = 0
        stop_serial = threading.Event()
        serial_thread: threading.Thread | None = None

        def emit(line: str) -> None:
            nonlocal line_number
            with lock:
                line_number += 1
                output.write(line)
                output.flush()
                print(f"{line_number:06d} {line}", end="", flush=True)

        def follow_serial(serial_path: Path) -> None:
            while not serial_path.exists() and not stop_serial.wait(0.05):
                pass
            if not serial_path.exists():
                return
            with serial_path.open("r", errors="replace") as serial:
                while True:
                    line = serial.readline()
                    if line:
                        emit(line)
                    elif stop_serial.wait(0.05):
                        # Drain bytes written immediately before process exit.
                        while line := serial.readline():
                            emit(line)
                        return

        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=environment,
            start_new_session=True,
        )
        if process.stdout is None:
            process.terminate()
            raise SystemExit("failed to capture command output")
        interrupted = False
        try:
            for line in process.stdout:
                emit(line)
                match = KERNEL_LOG_RE.match(line)
                if match and serial_thread is None:
                    serial_thread = threading.Thread(
                        target=follow_serial,
                        args=(Path(match.group(1)),),
                        name="86box-kernel-log",
                        daemon=True,
                    )
                    serial_thread.start()
        except KeyboardInterrupt:
            interrupted = True
            os.killpg(process.pid, signal.SIGTERM)
        try:
            returncode = process.wait(timeout=2.0 if interrupted else None)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            returncode = process.wait()
        if interrupted:
            # Flatpak may let its launcher exit before bwrap/86Box. Kill the
            # now-orphaned remainder of the dedicated capture process group.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        stop_serial.set()
        if serial_thread is not None:
            serial_thread.join(timeout=1.0)
    raise SystemExit(returncode)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    result.add_argument(
        "--window-class", default=WINDOW_CLASS,
        help="WM class of the emulator window (default 86Box; use Bochs to "
             "drive a Bochs SDL window with the same keys and screenshots)",
    )
    sub = result.add_subparsers(dest="command", required=True)

    wait = sub.add_parser("wait", help="wait for exactly one matching VM window")
    wait.add_argument("--title", default="RetroOS")
    wait.add_argument("--timeout", type=float, default=30.0)
    wait.set_defaults(function=command_wait)

    key = sub.add_parser("key", help="send named keys through XTest")
    key.add_argument("--title", default="RetroOS")
    key.add_argument("keys", nargs="+")
    key.set_defaults(function=command_key)

    typed = sub.add_parser("type", help="type printable ASCII text through XTest")
    typed.add_argument("--title", default="RetroOS")
    typed.add_argument("text")
    typed.set_defaults(function=command_type)

    click = sub.add_parser("click", help="click at coordinates relative to the VM window")
    click.add_argument("--title", default="RetroOS")
    click.add_argument("--button", type=int, default=1)
    click.add_argument("x", type=int)
    click.add_argument("y", type=int)
    click.set_defaults(function=command_click)

    raised = sub.add_parser("raise", help="raise the matching VM window")
    raised.add_argument("--title", default="RetroOS")
    raised.set_defaults(function=command_raise)

    shot = sub.add_parser("screenshot", help="capture the matching VM window as PNG")
    shot.add_argument("--title", default="RetroOS")
    shot.add_argument("output")
    shot.set_defaults(function=command_screenshot)

    log = sub.add_parser("log", help="show stable numbered lines from a diagnostic log")
    log.add_argument("--lines", type=int, default=100)
    log.add_argument("--follow", action="store_true")
    log.add_argument("path")
    log.set_defaults(function=command_log)

    capture = sub.add_parser("capture", help="run a command, save raw output, and print numbered lines")
    capture.add_argument("--log", required=True)
    capture.add_argument(
        "--kernel-log",
        action="store_true",
        help="ask run.sh's 86Box backend to mirror the RetroOS kernel log through COM1",
    )
    capture.add_argument("program", nargs=argparse.REMAINDER)
    capture.set_defaults(function=command_capture)
    return result


def main() -> None:
    global WINDOW_CLASS
    args = parser().parse_args()
    WINDOW_CLASS = args.window_class
    args.function(args)


if __name__ == "__main__":
    main()
