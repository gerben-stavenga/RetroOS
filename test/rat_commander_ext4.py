#!/usr/bin/env python3
"""RC must fall back to console stdio when ext4 contains a Linux /dev/tty inode."""
from pathlib import Path
import json
import shutil
import socket
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
UUID = "ea8c19a0-a2e3-4d14-9fd2-6955c176122c"


def run(*args):
    subprocess.run(list(map(str, args)), cwd=ROOT, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def main():
    run("bazelisk", "build", "//kernel:kernel.elf")
    with tempfile.TemporaryDirectory(prefix="retroos-rat-ext4-") as directory:
        work = Path(directory)
        root = work / "root"
        runtime = root / "boot/retroos"
        (runtime / "RETROOS").mkdir(parents=True)
        (root / "home/retroos/RC").mkdir(parents=True)
        (root / "dev").mkdir()
        shutil.copyfile(ROOT / "showcase-bundle/COMMANDER/RC/RC.EXE", root / "home/retroos/RC/RC.EXE")
        (runtime / "RETROOS/BOOT.INI").write_text(
            f'[bundle]\nsource=UUID={UUID}\nsubdir=/boot/retroos\n[mount "linux"]\nsource=UUID={UUID}\npath=/\naccess=ram\n'
            f'[mount "dos"]\nsource=UUID={UUID}\nsubdir=/home/retroos\n'
            'path=/home/retroos\ndrive=C\naccess=ram\n')
        image = work / "root.img"
        with image.open("wb") as stream:
            stream.truncate(128 * 1024 * 1024)
        run("mkfs.ext4", "-q", "-F", "-U", UUID, "-d", root, image)
        commands = work / "devices.txt"
        commands.write_text("cd /dev\nmknod tty c 5 0\n")
        run("debugfs", "-w", "-f", commands, image)
        inode = subprocess.check_output(
            ["debugfs", "-R", "stat /dev/tty", str(image)], stderr=subprocess.DEVNULL)
        assert b"character special" in inode, inode

        grub = work / "iso/boot/grub"
        grub.mkdir(parents=True)
        shutil.copyfile(ROOT / "bazel-bin/kernel/kernel.elf", grub.parent / "kernel.elf")
        shutil.copyfile(runtime / "RETROOS/BOOT.INI", grub.parent / "BOOT.INI")
        (grub.parent / "RETROOS.INI").write_text('[system]\nstart=C:\\RC\\RC.EXE\n')
        (grub / "grub.cfg").write_text(
            'set timeout=0\nmenuentry RetroOS {\n'
            ' multiboot2 /boot/kernel.elf\n'
            ' module2 /boot/BOOT.INI retroos.config=boot\n'
            ' module2 /boot/RETROOS.INI retroos.config=ini\n'
            ' boot\n}\n')
        iso = work / "boot.iso"
        run("grub-mkrescue", "-o", iso, work / "iso")
        log = work / "guest.log"
        qmp = work / "qmp.sock"
        process = subprocess.Popen([
            "qemu-system-x86_64", "-accel", "tcg", "-cpu", "max", "-m", "512",
            "-cdrom", str(iso), "-boot", "order=d",
            "-drive", f"file={image},format=raw", "-display", "none", "-serial", "none",
            "-debugcon", f"file:{log}", "-no-reboot",
            "-qmp", f"unix:{qmp},server=on,wait=off",
            "-fw_cfg", "name=opt/cmdline,string=/home/retroos/RC/RC.EXE",
            "-fw_cfg", "name=opt/cwd,string=/home/retroos/RC",
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        def text():
            return log.read_text(errors="replace") if log.exists() else ""

        def wait_for(predicate, timeout=60):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                output = text()
                assert not any(s in output for s in (
                    "Rat Commander error:", "!!! FATAL !!!", "[LINUX] fatal",
                    "[mem] exit tid=1 code=1")), output[-6000:]
                if predicate(output):
                    return
                assert process.poll() is None, output[-6000:]
                time.sleep(.1)
            raise AssertionError(text()[-6000:])

        try:
            wait_for(lambda output: "event_loop entered" in output)
            # RC probes terminal capabilities before its first frame.
            time.sleep(5)
            with socket.socket(socket.AF_UNIX) as connection:
                connection.connect(str(qmp))
                connection.settimeout(5)
                with connection.makefile("rwb") as stream:
                    stream.readline()

                    def call(command, **arguments):
                        stream.write((json.dumps(dict(execute=command, arguments=arguments)) + "\n").encode())
                        stream.flush()
                        while True:
                            response = json.loads(stream.readline())
                            assert "error" not in response, response
                            if "return" in response:
                                return

                    call("qmp_capabilities")
                    call("human-monitor-command", **{"command-line": "sendkey f10"})
                    time.sleep(.5)
                    call("human-monitor-command", **{"command-line": "sendkey ret"})
                    wait_for(lambda output: "[mem] exit tid=1 code=0" in output, 15)
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)
    print("PASS: Rat Commander starts and quits with an ext4 /dev/tty device inode (TCG)")


if __name__ == "__main__":
    main()
