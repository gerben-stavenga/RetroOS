#!/usr/bin/env python3
"""Native regression: mount an existing file on ext4 as C:, plus an ISO.

All disks are private fixtures. Covers rw/ro/ram and the GRUB protection
argument, checking the backing file after QEMU exits rather than trusting logs.
"""
import os
from pathlib import Path
import shutil
import subprocess
import struct
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
UUID = '12345678-1234-1234-1234-123456789abc'

ASM = r'''
bits 16
org 100h
mov dx,dll
mov ax,3d02h
int 21h
jc fail
mov bx,ax
mov ah,3eh
int 21h
mov dx,output
xor cx,cx
mov ah,3ch
int 21h
%ifdef READONLY
jnc fail
mov ax,4c00h
int 21h
%else
jc fail
mov bx,ax
mov dx,payload
mov cx,4
mov ah,40h
int 21h
jc fail
cmp ax,4
jne fail
mov ah,3eh
int 21h
mov dx,output
mov ax,3d00h
int 21h
jc fail
mov bx,ax
mov dx,buffer
mov cx,4
mov ah,3fh
int 21h
jc fail
cmp ax,4
jne fail
cmp dword [buffer],0x53534150
jne fail
mov ah,3eh
int 21h
mov dx,iso
mov ax,3d00h
int 21h
jc fail
mov bx,ax
mov ah,3eh
int 21h
mov ax,4c00h
int 21h
%endif
fail:
mov ax,4c49h
int 21h
dll db 'C:\RETROOS\WINDOWS\SYSTEM32\KERNEL32.DLL',0
output db 'C:\RESULT.TXT',0
iso db 'D:\HELLO.TXT',0
payload db 'PASS'
buffer times 4 db 0
'''


def run(*args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True,
                          stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, **kwargs)


def main():
    if not os.access('/dev/kvm', os.R_OK | os.W_OK):
        raise SystemExit('This native regression requires KVM')
    subprocess.run(['bazelisk', 'build', '//:boot_disk'], cwd=ROOT, check=True)
    boot_source = (ROOT / 'bazel-bin/boot_disk.bin').resolve()
    with tempfile.TemporaryDirectory(prefix='retroos-file-mount-') as directory:
        work = Path(directory)
        (work/'probe.asm').write_text(ASM)
        (work/'iso').mkdir()
        (work/'iso/HELLO.TXT').write_text('optical image fixture\n')
        run('xorriso', '-as', 'mkisofs', '-quiet', '-o', work/'game.iso', work/'iso')
        for access, protected, partitioned in [('rw', False, False), ('ro', False, False), ('ram', False, False), ('rw', True, False), ('rw', False, True)]:
            case = work / (access + ('-protected' if protected else '') + ('-partitioned' if partitioned else ''))
            tree = case/'tree'
            home = tree/'home/priv-gerben/project/RetroOS/build'
            home.mkdir(parents=True)
            image = home/'data.bin'
            with image.open('wb') as f:
                f.truncate(16*1024*1024)
            run('mkfs.fat', '-F', '16', image)
            args = ['nasm', '-f', 'bin', work/'probe.asm', '-o', work/'MOUNT.COM']
            if access == 'ro': args += ['-DREADONLY']
            run(*args)
            run('mcopy', '-i', image, work/'MOUNT.COM', '::MOUNT.COM')
            if partitioned:
                payload = image.read_bytes()
                mbr = bytearray(512)
                mbr[450] = 0x06
                struct.pack_into('<II', mbr, 454, 2048, len(payload)//512)
                mbr[510:512] = b'\x55\xaa'
                with image.open('wb') as stream:
                    stream.write(mbr)
                    stream.seek(1048576)
                    stream.write(payload)
            shutil.copyfile(work/'game.iso', tree/'home/priv-gerben/game.iso')
            for parent in [tree, *tree.rglob('*')]:
                parent.chmod(0o775 if parent.is_dir() else 0o664)
            outer = case/'linux.img'
            with outer.open('wb') as f: f.truncate(64*1024*1024)
            run('mkfs.ext4', '-q', '-F', '-b', '4096', '-U', UUID, '-d', tree, outer)
            boot = case/'boot.img'
            shutil.copyfile(boot_source, boot)
            config = case/'RETROOS.INI'
            config.write_text(f'''[system]
start=C:\\MOUNT.COM
[environment]
TEST=/home/retroos/MOUNT.COM
[mount "linux"]
source=UUID={UUID}
path=/
access=rw
grant=/home/priv-gerben
[mount "data"]
source=file:/home/priv-gerben/project/RetroOS/build/data.bin
{'partition=1' if partitioned else ''}
path=/home/retroos
drive=C
access={access}
[mount "cd"]
source=file:/home/priv-gerben/game.iso
format=iso9660
path=/cdrom
drive=D
access=ro
''')
            run('mcopy', '-o', '-i', str(boot)+'@@1048576', config, '::RETROOS/RETROOS.INI')
            log = case/'klog'
            argv = ['qemu-system-x86_64', '-accel', 'kvm', '-cpu', 'host', '-m', '256',
                    '-display', 'none', '-serial', 'none', '-audiodev', 'none,id=snd0',
                    '-drive', f'file={boot},format=raw,snapshot=on',
                    '-drive', f'file={outer},format=raw',
                    '-device', f'VGA,romfile={ROOT}/third_party/vgabios/vgabios-stdvga.bin',
                    '-debugcon', f'file:{log}', '-no-reboot']
            if protected:
                grub = case/'grub.cfg'
                run('mcopy', '-i', str(boot)+'@@1048576', '::boot/grub/grub.cfg', grub)
                grub.write_text(grub.read_text().replace('multiboot2 /kernel.elf', 'multiboot2 /kernel.elf ram-overlay'))
                run('mcopy', '-o', '-i', str(boot)+'@@1048576', grub, '::boot/grub/grub.cfg')
            stderr = (case/'stderr').open('w')
            process = subprocess.Popen(argv, stderr=stderr)
            try:
                deadline = time.monotonic() + 35
                while time.monotonic() < deadline:
                    content = log.read_text(errors='replace') if log.exists() else ''
                    if '[mem] exit tid=1 code=' in content or 'PANIC' in content or process.poll() is not None:
                        break
                    time.sleep(.1)
                if '[mem] exit tid=1 code=0' not in content or 'PANIC' in content:
                    raise RuntimeError(content + '\n' + (case/'stderr').read_text())
            finally:
                if process.poll() is None: process.terminate()
                process.wait(timeout=5)
                stderr.close()
            extracted = case/'after.bin'
            run('debugfs', '-R', f'dump /home/priv-gerben/project/RetroOS/build/data.bin {extracted}', outer)
            result = subprocess.run(['mtype', '-i', str(extracted)+('@@1048576' if partitioned else ''), '::RESULT.TXT'], capture_output=True)
            if access == 'rw' and not protected:
                assert result.returncode == 0 and result.stdout == b'PASS', result
            else:
                assert result.returncode != 0, 'RAM/read-only writes reached the original image'
            print(f'PASS: {access}, protected={protected}, partitioned={partitioned}', flush=True)
    print('PASS: native file-backed C:, ISO, RW system-file opens, and persistence policies')


if __name__ == '__main__':
    main()
