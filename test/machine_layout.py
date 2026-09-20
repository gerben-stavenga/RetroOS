#!/usr/bin/env python3
"""Boot an installed-machine layout: explicit UUID, read-only runtime, persistent C:."""
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
UUID = "ea8c19a0-a2e3-4d14-9fd2-6955c176122c"


def run(*args):
    subprocess.run(list(map(str, args)), cwd=ROOT, check=True, stdout=subprocess.DEVNULL)


def boot(work, name, image, decoy, uuid, expected, reverse=False, uefi=False):
    tree = work / name
    grub = tree / "boot/grub"
    grub.mkdir(parents=True)
    shutil.copyfile(ROOT / "bazel-bin/kernel/kernel.elf", tree / "boot/kernel.elf")
    (grub / "grub.cfg").write_text(f'''set timeout=0
menuentry "installed layout" {{
    insmod all_video
    set gfxmode=auto
    set gfxpayload=keep
    multiboot /boot/kernel.elf retroos.root={uuid} retroos.c-root=/home/retroos retroos.runtime=/boot/retroos/RETROOS
    boot
}}
''')
    iso = work / (name + ".iso")
    run("grub-mkrescue", "-o", iso, tree)
    log = work / (name + ".log")
    disks = [image, decoy] if reverse else [decoy, image]
    args = ["qemu-system-i386", "-m", "128", "-cdrom", str(iso), "-boot", "order=d",
            "-display", "none", "-serial", "none", "-no-reboot", "-debugcon", "file:" + str(log),
            "-fw_cfg", "name=opt/cmdline,string=/home/retroos/PROBE.ELF"]
    if uefi:
        args[0] = "qemu-system-x86_64"
        shutil.copyfile("/usr/share/OVMF/OVMF_VARS_4M.fd", work / "vars.fd")
        args += ["-machine", "q35", "-cpu", "max",
                 "-drive", "if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd",
                 "-drive", f"if=pflash,format=raw,file={work / 'vars.fd'}",
                 "-drive", f"file={image},format=raw,if=none,id=root",
                 "-device", "nvme,drive=root,serial=layout-test",
                 "-drive", f"file={decoy},format=raw,if=none,id=decoy",
                 "-device", "piix3-ide,id=extra-ide",
                 "-device", "ide-hd,drive=decoy,bus=extra-ide.0"]
    else:
        for disk in disks:
            args += ["-drive", f"file={disk},format=raw"]
    process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 40
        while process.poll() is None and time.monotonic() < deadline:
            text = log.read_text(errors="replace") if log.exists() else ""
            if expected in text or "LAYOUT-FAIL" in text:
                break
            time.sleep(.1)
    finally:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=5)
    text = log.read_text(errors="replace")
    assert expected in text and "LAYOUT-FAIL" not in text, text
    print("PASS:", name)


def main():
    run("bazelisk", "build", "//:machine_boot_tar")
    with tempfile.TemporaryDirectory(prefix="retroos-machine-test-") as temp:
        work = Path(temp)
        root = work / "root"
        home = root / "home/retroos"
        for name in ("home/retroos/RETROOS", "boot/grub", "etc", "usr"):
            (root / name).mkdir(parents=True, exist_ok=True)
        with tarfile.open(ROOT / "bazel-bin/machine_boot_tar.tar") as archive:
            archive.extractall(root / "boot/retroos", filter="data")
        (home / "STATE.DAT").write_bytes(b"INIT")
        (home / "STATE.DAT").chmod(0o664)
        home.chmod(0o2775)
        # Deliberately writable underneath: the runtime mount must deny writes.
        runtime = root / "boot/retroos/RETROOS/TEST.DAT"
        runtime.write_bytes(b"BOOT")
        runtime.chmod(0o666)
        source = work / "probe.c"
        source.write_text(r'''
static int call(int n,int a,int b,int c) { int r;
 __asm__ volatile("int $0x80":"=a"(r):"0"(n),"b"(a),"c"(b),"d"(c):"memory"); return r; }
static void say(char *s,int n) {call(4,1,(int)s,n);}
void _start(void) {
 char b[4];
 int f=call(5,(int)"/home/retroos/RETROOS/TEST.DAT",0,0);
 if(f<0 || call(3,f,(int)b,4)!=4 || b[0]!='B') goto fail;
 call(6,f,0,0);
 f=call(5,(int)"/home/retroos/RETROOS/TEST.DAT",2,0);
 if(f>=0) { if(call(4,f,(int)"FAIL",4)>=0) goto fail; call(6,f,0,0); }
 f=call(5,(int)"/home/retroos/STATE.DAT",2,0);
 if(f<0 || call(3,f,(int)b,4)!=4) goto fail;
 call(19,f,0,0);
 if(call(4,f,(int)"PASS",4)!=4) goto fail;
 call(6,f,0,0);
 if(b[0]=='P') say("LAYOUT-PERSISTED\n",17);
 else say("LAYOUT-WROTE\n",13);
 call(1,0,0,0); for(;;){}
fail: say("LAYOUT-FAIL\n",12);call(1,1,0,0);for(;;){}
}
''')
        run("gcc", "-m32", "-static", "-nostdlib", "-no-pie", "-fno-pic", "-fno-stack-protector",
            "-O2", "-e", "_start", "-o", home / "PROBE.ELF", source)
        image = work / "root.img"
        with image.open("wb") as stream:
            stream.truncate(128 * 1024 * 1024)
        run("mkfs.ext4", "-q", "-F", "-U", UUID, "-d", root, image)
        decoy = work / "decoy.img"
        with decoy.open("wb") as stream:
            stream.truncate(32 * 1024 * 1024)
        run("mkfs.fat", decoy)
        run("mmd", "-i", decoy, "::RETROOS")
        boot(work, "explicit-root", image, decoy, UUID, "LAYOUT-WROTE")
        boot(work, "reordered-disks", image, decoy, UUID, "LAYOUT-PERSISTED", reverse=True)
        boot(work, "missing-root", image, decoy, "00000000-0000-0000-0000-000000000001",
             "Configured root UUID not found")
        boot(work, "uefi-installed-root", image, decoy, UUID, "LAYOUT-PERSISTED", uefi=True)
        run("e2fsck", "-fn", image)


if __name__ == "__main__":
    main()
