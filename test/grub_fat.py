#!/usr/bin/env python3
"""GRUB hands off the kernel; FAT supplies the root, on disk or as a module."""
import pathlib
import shutil
import struct
import subprocess
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent


def run(*args):
    subprocess.run([str(arg) for arg in args], cwd=ROOT, check=True)


def make_fat(work, name, bits, size, root):
    image = work / name
    with image.open("wb") as stream:
        stream.truncate(size)
    run("mkfs.fat", "-F", bits, image)
    if root:
        run("mmd", "-i", image, "::home", "::home/retroos")
        run("mcopy", "-i", image, work / "probe.elf", "::home/retroos/PROBE.ELF")
        run("mcopy", "-i", image, work / "payload", "::home/retroos/Mixed case filename.txt")
        run("mcopy", "-i", image, work / "empty", "::home/retroos/WRITE.TXT")
        run("mcopy", "-i", image, ROOT / "bazel-bin/test/dos/lfnprobe/LFNPROBE.COM", "::home/retroos/LFNPROBE.COM")
    else:
        run("mmd", "-i", image, "::EFI")
    return image


def boot(work, name, image, module, expected, command="PROBE.ELF", marker="FAT-ROOT-RW-OK", memory=256):
    tree = work / name
    grub = tree / "boot/grub"
    grub.mkdir(parents=True)
    shutil.copyfile(ROOT / "bazel-bin/kernel/kernel.elf", tree / "boot/kernel.elf")
    commands = ["set timeout=0", "set default=0", 'menuentry "FAT root" {',
                "terminal_output console", "multiboot /boot/kernel.elf"]
    if module:
        shutil.copyfile(image, tree / "boot/root.img")
        commands.append("module /boot/root.img retroos.mount=/")
    commands.extend(["boot", "}"])
    (grub / "grub.cfg").write_text("\n".join(commands) + "\n")
    iso = work / (name + ".iso")
    run("grub-mkrescue", "-o", iso, tree)
    log = work / (name + ".log")
    args = ["qemu-system-i386", "-m", str(memory), "-cpu", "pentium3", "-cdrom", str(iso),
            "-boot", "order=d", "-display", "none", "-serial", "none", "-no-reboot",
            "-debugcon", "file:" + str(log), "-fw_cfg", "name=opt/cmdline,string=" + command]
    if not module:
        args.extend(["-drive", f"file={image},format=raw,snapshot=on"])
    process = subprocess.Popen(args, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 25
        while process.poll() is None and time.monotonic() < deadline:
            output = log.read_text(errors="replace") if log.exists() else ""
            if marker in output or any(error in output for error in ["FAT-PROBE-FAILED", "LFN-FAIL", "FATAL"]):
                break
            time.sleep(0.1)
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
    text = log.read_text(errors="replace")
    if expected not in text or marker not in text or any(
        error in text for error in ["FAT-PROBE-FAILED", "LFN-FAIL", "FATAL", "panicked"]
    ):
        raise AssertionError(f"{name} failed:\n{text}")
    print(f"PASS: {name}", flush=True)


def main():
    run("bazelisk", "build", "//kernel:kernel_elf", "//test/dos/lfnprobe:lfnprobe_com")
    with tempfile.TemporaryDirectory(prefix="retroos-fat-") as scratch:
        work = pathlib.Path(scratch)
        run("gcc", "-m32", "-static", "-nostdlib", "-no-pie", "-fno-pic", "-fno-stack-protector",
            "-O2", "-e", "_start", "-o", work / "probe.elf", "test/fat_probe.c")
        (work / "payload").write_bytes(b"FAT-DATA")
        (work / "empty").write_bytes(b"")
        fat12 = make_fat(work, "fat12.img", 12, 1440 * 1024, True)
        fat16 = make_fat(work, "fat16.img", 16, 16 * 1024 * 1024, True)
        fat32 = make_fat(work, "fat32.img", 32, 64 * 1024 * 1024, True)
        esp = make_fat(work, "esp.img", 12, 1440 * 1024, False)
        disk = work / "partitioned.img"
        # An EFI-like FAT partition comes first; only the second has our root.
        mbr = bytearray(512)
        mbr[510:512] = b"\x55\xaa"
        with disk.open("wb") as stream:
            stream.truncate(8192 * 512 + fat16.stat().st_size)
            for index, (image, start, kind) in enumerate([(esp, 2048, 1), (fat16, 8192, 6)]):
                offset = 446 + index * 16
                mbr[offset + 4] = kind
                struct.pack_into("<II", mbr, offset + 8, start, image.stat().st_size // 512)
                stream.seek(start * 512)
                with image.open("rb") as source:
                    shutil.copyfileobj(source, stream)
            stream.seek(0)
            stream.write(mbr)
        boot(work, "fat16-partition-root", disk, False, "Mounting FAT root (16 MB)")
        boot(work, "fat16-whole-disk-root", fat16, False, "Mounting FAT root (16 MB)")
        boot(work, "fat12-module-root", fat12, True, "Multiboot FAT (1 MB, volatile overlay)")
        boot(work, "fat32-module-root", fat32, True, "Multiboot FAT (64 MB, volatile overlay)")
        for label, image in [("fat12", fat12), ("fat16", fat16), ("fat32", fat32)]:
            boot(work, label + "-lfn", image, True, "Multiboot FAT", "LFNPROBE.COM", "LFN-ALL-OK",
                 memory=32 if label == "fat12" else 256)


if __name__ == "__main__":
    main()
