#!/usr/bin/env python3
"""Exercise ATA DMA/PIO on a sparse GPT disk with a FAT partition beyond 2 TiB.

Requires QEMU, gcc, mtools, mkfs.fat and Bazel. Uses only temporary disks;
the apparent 2 TiB disk occupies a few MiB on a sparse-file filesystem.
"""
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import time
import uuid
import zlib

ROOT = Path(__file__).resolve().parents[1]
FIRST = (1 << 32) + 2048
SECTORS = 64 * 1024 * 1024 // 512
TOTAL = FIRST + SECTORS + 2048


def run(*args):
    subprocess.run(list(map(str, args)), cwd=ROOT, check=True, stdout=subprocess.DEVNULL)


def make_disk(work):
    fat = work / "fat.img"
    with fat.open("wb") as stream:
        stream.truncate(SECTORS * 512)
    run("mkfs.fat", "-F", "16", "-i", "BEEF0048", fat)
    run("mmd", "-i", fat, "::/RETROOS")
    (work / "RETROOS.INI").write_text('[environment]\nTEST=PROBE.ELF\nSERIAL=COM1\n')
    run("mcopy", "-i", fat, work / "RETROOS.INI", "::/RETROOS/RETROOS.INI")
    run("gcc", "-m32", "-static", "-nostdlib", "-no-pie", "-fno-pic",
        "-fno-stack-protector", "-O2", "-e", "_start", '-DPROBE_NAME="LBA48"',
        "-o", work / "PROBE.ELF", ROOT / "test/ata_chs_probe.c")
    payload = bytes((i * 37 + (i >> 9)) & 255 for i in range(256 * 1024))
    (work / "PROBE.DAT").write_bytes(payload)
    for name in ("PROBE.ELF", "PROBE.DAT"):
        run("mcopy", "-i", fat, work / name, "::/" + name)
    entries = bytearray(128 * 128)
    entries[:16] = uuid.UUID("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7").bytes_le
    entries[16:32] = uuid.uuid4().bytes_le
    struct.pack_into("<QQ", entries, 32, FIRST, FIRST + SECTORS - 1)
    disk_id = uuid.uuid4().bytes_le

    def header(current, backup, array):
        data = bytearray(512)
        struct.pack_into("<8sIIIIQQQQ16sQIII", data, 0, b"EFI PART", 0x10000, 92,
                         0, 0, current, backup, 34, TOTAL - 34, disk_id,
                         array, 128, 128, zlib.crc32(entries))
        struct.pack_into("<I", data, 16, zlib.crc32(data[:92]))
        return data

    disk = work / "data.img"
    with disk.open("wb") as stream:
        stream.truncate(TOTAL * 512)
        mbr = bytearray(512)
        mbr[450] = 0xee
        struct.pack_into("<II", mbr, 454, 1, 0xffffffff)
        mbr[510:] = b"\x55\xaa"
        stream.seek(0)
        stream.write(mbr)
        stream.write(header(1, TOTAL - 1, 2))
        stream.write(entries)
        stream.seek((TOTAL - 33) * 512)
        stream.write(entries)
        stream.write(header(TOTAL - 1, 1, TOTAL - 33))
        stream.seek(FIRST * 512)
        with fat.open("rb") as source:
            shutil.copyfileobj(source, stream)
    return disk, payload


def test_transport(work, disk, payload, pio):
    # The boot copy supplies runtime files; the high FAT partition owns C:.
    boot = work / "boot.img"
    shutil.copyfile(ROOT / "bazel-bin/boot_disk.bin", boot)
    configs = {
        "BOOT.INI": '[bundle]\nsource=UUID=5E77-0002\nsubdir=/\n'
                    '[mount "data"]\nsource=UUID=BEEF-0048\npath=/\ndrive=C\naccess=rw\n',
        "RETROOS.INI": '[environment]\nTEST=PROBE.ELF\nSERIAL=COM1\n',
    }
    for name, text in configs.items():
        path = work / name
        path.write_text(text)
        run("mcopy", "-o", "-i", str(boot) + "@@1048576", path, "::/RETROOS/" + name)
    grub = work / "grub.cfg"
    grub.write_text('set timeout=0\nmenuentry "LBA48 test" {\n'
                    'multiboot /kernel.elf serial=com1\nboot\n}\n')
    run("mcopy", "-o", "-i", str(boot) + "@@1048576", grub, "::/boot/grub/grub.cfg")
    command = [os.environ.get("RETROOS_QEMU_BIN", "qemu-system-x86_64"),
               "-M", "isapc" if pio else "pc", "-cpu", "pentium3", "-m", "128",
               "-drive", f"file={boot},format=raw,index=0",
               "-drive", f"file={disk},format=raw,index=1",
               "-display", "none", "-serial", "none", "-monitor", "none",
               "-debugcon", "stdio", "-no-reboot"]
    log = work / "boot.log"
    with log.open("wb") as output:
        process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT, cwd=ROOT)
        try:
            deadline = time.monotonic() + 90
            while process.poll() is None and time.monotonic() < deadline:
                text = log.read_text(errors="replace")
                if any(marker in text for marker in ("All commands done", "FATAL")):
                    break
                time.sleep(.1)
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
    text = log.read_text(errors="replace")
    transport = "PIO" if pio else "DMA"
    assert f"ATA: ata1 LBA48 {transport}" in text, text[-12000:]
    # Linux stdout is the guest screen, while debugcon records the exit status.
    assert "[mem] exit tid=1 code=0 " in text and "FATAL" not in text, text[-12000:]
    saved = subprocess.check_output(["mtype", "-i", f"{disk}@@{FIRST * 512}", "::/PROBE.DAT"])
    assert saved == bytes(b ^ 0xa5 for b in payload), "Writes did not persist on the backing disk"
    print(f"PASS: LBA48 {transport} GPT discovery and read/write/reopen beyond 2 TiB")


def main():
    run(os.environ.get("BAZEL", "bazelisk"), "build", "//:boot_disk")
    for pio in (False, True):
        with tempfile.TemporaryDirectory(prefix="retroos-lba48-") as folder:
            work = Path(folder)
            disk, payload = make_disk(work)
            test_transport(work, disk, payload, pio)


if __name__ == "__main__":
    main()
