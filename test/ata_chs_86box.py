#!/usr/bin/env python3
"""Read/write a CHS-only ~20 MiB IDE disk, using an isolated copy of a TX97 VM.

Requires the configured 86Box VM/ROMs used by run.sh, mtools, gcc and Bazel.
Uses no persistent user disk. Run normally for DMA and with --pio for a
CMD640 controller. The separate boot disk retains run.sh's BIOS workaround.
"""
import argparse
import configparser
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent


def run(*args):
    subprocess.run(list(map(str, args)), cwd=ROOT, check=True, stdout=subprocess.DEVNULL)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vm", type=Path)
    parser.add_argument("--pio", action="store_true", help="use a CMD640 controller without bus mastering")
    args = parser.parse_args()
    flatpak = ""
    if shutil.which("flatpak"):
        flatpak = next((s for s in subprocess.check_output(
            ["flatpak", "list", "--app", "--columns=application"], text=True).splitlines()
            if "86box" in s.lower()), "")
    template = args.vm or (Path.home() / ".var/app" / flatpak / "data/86Box/RetroOS"
                          if flatpak else Path.home() / ".local/share/86Box/RetroOS")
    assert (template / "86box.cfg").exists(), "Pass --vm with a configured TX97 VM"
    run(os.environ.get("BAZEL", "bazelisk"), "build", "//:boot_disk")
    with tempfile.TemporaryDirectory(prefix="retroos-ata-chs-") as temp:
        work = Path(temp)
        vm = work / "CHS-Test"
        vm.mkdir()
        shutil.copytree(template / "nvr", vm / "nvr")
        boot = work / "boot.bin"
        shutil.copyfile(ROOT / "bazel-bin/boot_disk.bin", boot)
        with boot.open("r+b") as stream:
            stream.truncate(1024 * 16 * 63 * 512)
        data = work / "data.bin"
        with data.open("wb") as stream:
            stream.truncate(615 * 4 * 17 * 512)
        run("mkfs.fat", "-F", "16", data)
        run("mmd", "-i", data, "::/RETROOS")
        run("gcc", "-m32", "-static", "-nostdlib", "-no-pie", "-fno-pic",
            "-fno-stack-protector", "-O2", "-e", "_start", "-o", work / "PROBE.ELF",
            ROOT / "test/ata_chs_probe.c")
        # Allocate beyond cylinder 256 as well as crossing tracks and heads.
        with (work / "PADDING.BIN").open("wb") as stream:
            stream.truncate(10 * 1024 * 1024)
        payload = bytes((i * 37 + (i >> 9)) & 255 for i in range(256 * 1024))
        (work / "PROBE.DAT").write_bytes(payload)
        (work / "CONFIG.SYS").write_text("TEST=PROBE.ELF\nSERIAL=COM1\n")
        for name in ("PADDING.BIN", "PROBE.DAT", "PROBE.ELF"):
            run("mcopy", "-i", data, work / name, "::/" + name)
        run("mmd", "-i", data, "::/CONFIG")
        run("mcopy", "-i", data, work / "CONFIG.SYS", "::/CONFIG/CONFIG.SYS")
        # Early serial logs verify discovery/addressing, before CONFIG.SYS.
        (work / "grub.cfg").write_text('set timeout=0\nmenuentry "CHS test" {\n'
                                      'multiboot /kernel.elf serial=com1\nboot\n}\n')
        run("mcopy", "-o", "-i", str(boot) + "@@1048576", work / "grub.cfg", "::/boot/grub/grub.cfg")
        serial = work / "serial"
        for suffix in (".in", ".out"):
            os.mkfifo(str(serial) + suffix)
        fd = os.open(str(serial) + ".out", os.O_RDONLY | os.O_NONBLOCK)
        config = configparser.ConfigParser(interpolation=None)
        config.read(template / "86box.cfg")
        assert config["Machine"]["machine"] == "tx97", "Test requires a TX97 template"
        config["General"]["kbd_req_capture"] = "0"
        config["Sound"]["sndcard"] = "none"
        if args.pio:
            config["Storage controllers"]["hdc"] = "ide_cmd640_pci"
        config["Ports (COM & LPT)"] = {"serial1_device": "pipe", "serial2_device": "none"}
        config["Named Pipe (COM) #1"] = {"path": str(serial), "mode": "1", "reconnect": "1"}
        config["Hard disks"] = {
            "hdd_01_fn": str(boot), "hdd_01_parameters": f"63, 16, {boot.stat().st_size // (512 * 16 * 63)}, 0, ide",
            "hdd_01_ide_channel": "0:0", "hdd_02_fn": str(data),
            "hdd_02_parameters": "17, 4, 615, 0, ide", "hdd_02_ide_channel": "0:1",
        }
        with (vm / "86box.cfg").open("w") as stream:
            config.write(stream)
        source = Path(os.environ.get("RETROOS_86BOX_SOURCE", ROOT.parent / "86Box"))
        binary = os.environ.get("BOX86")
        command = [binary] if binary else []
        if not command:
            if flatpak:
                command = ["flatpak", "run", "--devel", "--env=QT_QPA_PLATFORM=xcb",
                           "--filesystem=" + str(work)]
                if (source / "build/regular/src/86Box").exists():
                    command += ["--filesystem=" + str(source),
                                "--command=" + str(source / "build/regular/src/86Box")]
                command += [flatpak]
            else:
                command = [str(source / "build/regular/src/86Box") if
                           (source / "build/regular/src/86Box").exists() else "86box"]
        process = subprocess.Popen(command + ["--vmpath", str(vm)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   env=dict(os.environ, QT_QPA_PLATFORM="xcb"), start_new_session=True)
        output = bytearray()
        try:
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline:
                try:
                    output.extend(os.read(fd, 65536))
                except BlockingIOError:
                    pass
                (work / "boot.log").write_bytes(output)
                if any(marker in output for marker in (b"CHS-RW-OK", b"CHS-RW-FAILED", b"FATAL")):
                    break
                if process.poll() is not None:
                    break
                time.sleep(.1)
        finally:
            # The probe has closed its file before reporting success. Stop the
            # whole Flatpak process group before checking the backing image.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            os.close(fd)
        text = output.decode(errors="replace")
        expected = "ATA: ata1 CHS " + ("PIO" if args.pio else "DMA")
        assert expected in text and "CHS-RW-OK" in text, text[-12000:]
        assert "FATAL" not in text and "CHS-RW-FAILED" not in text, text[-12000:]
        saved = subprocess.check_output(["mtype", "-i", str(data), "::/PROBE.DAT"])
        assert saved == bytes(b ^ 0xa5 for b in payload), "Backing disk did not retain writes"
        transport = next(line for line in text.splitlines() if "ATA: ata1" in line)
        print(f"PASS: 615/4/17 CHS disk read/write/reopen and persistent contents ({transport})")


if __name__ == "__main__":
    main()
