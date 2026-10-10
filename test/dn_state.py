#!/usr/bin/env python3
"""Exercise real DN configuration/history saves with boot files on a read-only disk."""
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time

from boot_fixture import prepare_boot

ROOT = Path(__file__).resolve().parent.parent


def run(*args):
    subprocess.run(list(map(str, args)), cwd=ROOT, check=True, stdout=subprocess.DEVNULL)


def session(work, disk, save_config):
    ini = (ROOT / "etc/RETROOS.INI").read_text().split('[mount "session"]', 1)[0]
    # A persistent DN directory is an explicit mount, including its runtime.
    from vm_mount_config import volumes
    ident = volumes(disk)[0][1]
    ini += (f'[mount "data"]\nsource=UUID={ident}\npath=/home/retroos\ndrive=C\naccess=rw\n'
            f'[mount "dn"]\nsource=UUID={ident}\nsubdir=/DN\npath=/home/retroos/DN\naccess=rw\n')
    boot = prepare_boot(work, disk, ini)
    sock = work / "qmp"
    sock.unlink(missing_ok=True)
    log = work / "boot.log"
    process = subprocess.Popen([
        "qemu-system-i386", "-m", "128", "-display", "none", "-serial", "none",
        "-drive", f"file={boot},format=raw,snapshot=on",
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
        for directory in ("RETROOS", "DN", "TEMP"):
            run("mmd", "-i", disk, "::/" + directory)
        run("mcopy", "-i", disk, ROOT / "etc/RETROOS.INI", "::RETROOS/RETROOS.INI")
        for ext in ("COM", "PRG", "OVR", "DLG", "LNG", "HLP", "EDT", "EXT", "HGL", "MNU", "VWR", "XRN"):
            run("mcopy", "-i", disk, ROOT / f"boot-bundle/dn/DN.{ext}", f"::DN/DN.{ext}")
        for first in (True, False):
            session(work, disk, first)
            boot_log = subprocess.check_output(["mtype", "-i", str(disk), "::KLOG.TXT"])
            assert b"Interrupts initialized" in boot_log, boot_log
            assert b"Starting " in boot_log and b"DN.COM" in boot_log, boot_log
            # KLOG is now synchronized while DN runs and survives its restart.
            assert b"Dos Navigator  Version" in boot_log, boot_log
            assert b"Startup program exited" in boot_log, boot_log
            history = subprocess.check_output(["mtype", "-i", str(disk), "::DN/DN.HIS"])
            config = subprocess.check_output(["mtype", "-i", str(disk), "::DN/DN.CFG"])
            assert b"STATECHECK" in history, history
            assert len(config) > 1000
            temporary = subprocess.check_output(["mdir", "-i", str(disk), "::TEMP/"])
            assert b"0 bytes" in temporary, temporary
            listing = subprocess.check_output(["mdir", "-i", str(disk), "::RETROOS/"])
            assert b"0 bytes" in listing, listing
        print("PASS: real DN saves and reloads config/history separately; runtime and TEMP directories stay empty on data disk")


if __name__ == "__main__":
    main()
