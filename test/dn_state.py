#!/usr/bin/env python3
"""Exercise real DN configuration/history saves with boot files on a read-only disk."""
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent


def run(*args):
    subprocess.run(list(map(str, args)), cwd=ROOT, check=True, stdout=subprocess.DEVNULL)


def session(work, disk, save_config):
    sock = work / "qmp"
    sock.unlink(missing_ok=True)
    log = work / "boot.log"
    process = subprocess.Popen([
        "qemu-system-i386", "-m", "128", "-display", "none", "-serial", "none",
        "-drive", f"file={ROOT / 'bazel-bin/boot_disk.bin'},format=raw,snapshot=on",
        "-drive", f"file={disk},format=raw", "-debugcon", f"file:{log}",
        "-qmp", f"unix:{sock},server=on,wait=off", "-no-reboot"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            text = log.read_text(errors="replace") if log.exists() else ""
            if "Dos Navigator  Version 1.51" in text:
                break
            assert process.poll() is None, text
            time.sleep(.1)
        else:
            raise AssertionError("DN did not start: " + text)
        time.sleep(2)
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(5)
            connection.connect(str(sock))
            stream = connection.makefile("rwb")
            stream.readline()

            def call(command, args=None):
                stream.write((json.dumps(dict(execute=command, arguments=args or {})) + "\n").encode())
                stream.flush()
                while True:
                    result = json.loads(stream.readline())
                    assert "error" not in result, result
                    if "return" in result:
                        return result["return"]

            def key(name):
                call("human-monitor-command", {"command-line": "sendkey " + name})
                time.sleep(.3)

            call("qmp_capabilities")
            if save_config:
                # Run one command so DN has nonempty history to save.
                for char in "echo STATECHECK":
                    key("spc" if char == " " else ("shift-" + char.lower() if char.isupper() else char))
                key("ret")
                time.sleep(2)
                # Menu -> Options -> Configuration -> System Setup -> OK.
                for name in ("f10", "o", "ret", "ret", "ret"):
                    key(name)
            for name in ("alt-x", "ret"):
                key(name)
            time.sleep(2)
            call("quit")
        process.wait(timeout=5)
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
    text = log.read_text(errors="replace")
    assert "Startup program exited, restarting" in text, text
    assert "FATAL" not in text and "panicked" not in text, text


def main():
    run("bazelisk", "build", "//:boot_disk")
    with tempfile.TemporaryDirectory(prefix="retroos-dn-test-") as temp:
        work = Path(temp)
        disk = work / "data.img"
        with disk.open("wb") as stream:
            stream.truncate(64 * 1024 * 1024)
        run("mkfs.fat", "-F", "32", disk)
        for directory in ("RETROOS", "CONFIG", "CONFIG/DN", "TEMP"):
            run("mmd", "-i", disk, "::/" + directory)
        run("mcopy", "-i", disk, ROOT / "etc/CONFIG.SYS", "::CONFIG/CONFIG.SYS")
        for ext in ("EDT", "EXT", "HGL", "MNU", "VWR", "XRN"):
            run("mcopy", "-i", disk, ROOT / f"apps-boot/dn/DN.{ext}", f"::CONFIG/DN/DN.{ext}")
        for first in (True, False):
            session(work, disk, first)
            history = subprocess.check_output(["mtype", "-i", str(disk), "::CONFIG/DN/DN.HIS"])
            config = subprocess.check_output(["mtype", "-i", str(disk), "::CONFIG/DN/DN.CFG"])
            assert b"STATECHECK" in history, history
            assert len(config) > 1000
            run("mdir", "-i", disk, "::TEMP/DN.FLG")
            listing = subprocess.check_output(["mdir", "-i", str(disk), "::RETROOS/"])
            assert b"0 bytes" in listing, listing
        print("PASS: real DN saves and reloads config/history separately; runtime directory stays empty on data disk")


if __name__ == "__main__":
    main()
