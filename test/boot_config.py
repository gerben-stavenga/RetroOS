#!/usr/bin/env python3
"""Boot the unified config through GRUB modules and the VM data-disk profile.

Uses private images only. Verifies BIOS/UEFI config overrides, BusyBox startup,
and the shared rc executable alias when C: is an independently mounted disk.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent


def boot(args, log, stderr):
    with stderr.open('w') as errors:
        process = subprocess.Popen(args, stderr=errors)
        try:
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                text = log.read_text(errors='replace') if log.exists() else ''
                if '[mem] exit tid=1 code=' in text or 'PANIC' in text:
                    break
                if process.poll() is not None:
                    break
                time.sleep(.1)
            assert '[mem] exit tid=1 code=0' in text and 'PANIC' not in text, text[-8000:]
            return text
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)


def qemu(log):
    return ['qemu-system-x86_64', '-accel', 'kvm', '-cpu', 'host', '-m', '384',
            '-display', 'none', '-serial', 'none', '-debugcon', f'file:{log}',
            '-audiodev', 'none,id=snd0', '-no-reboot']


def main():
    subprocess.run(['bazelisk', 'build', '//:boot_disk', '//:root_module_base_image'], cwd=ROOT, check=True)
    with tempfile.TemporaryDirectory(prefix='retroos-boot-config-') as folder:
        work = Path(folder)
        tree = work/'iso'
        (tree/'boot/grub').mkdir(parents=True)
        shutil.copyfile(ROOT/'bazel-bin/kernel/kernel.elf', tree/'boot/kernel.elf')
        shutil.copyfile(ROOT/'bazel-bin/retroos-base.img', tree/'boot/base.img')
        (tree/'boot/RETROOS.INI').write_text('''[locale]
language=it-IT
[environment]
TEST=/bin/busybox true
[mount "session"]
source=bundle
path=/
drive=C
access=ram
''')
        (tree/'boot/grub/grub.cfg').write_text('''set timeout=0
menuentry test {
 multiboot2 /boot/kernel.elf ram-overlay
 if [ "$grub_platform" = "pc" ]; then
  set gfxpayload=text
 else
  insmod all_video
  set gfxmode=auto
  set gfxpayload=auto
 fi
 module2 /boot/base.img retroos.mount=/
 module2 /boot/RETROOS.INI retroos.config=ini
 boot
}
''')
        subprocess.run(['grub-mkrescue', '-o', str(work/'boot.iso'), str(tree)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for firmware in ('bios', 'uefi'):
            log = work/(firmware+'.log')
            args = qemu(log) + ['-cdrom', str(work/'boot.iso'), '-boot', 'd']
            if firmware == 'uefi':
                shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', work/'vars.fd')
                args += ['-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd',
                         '-drive', f'if=pflash,format=raw,file={work}/vars.fd']
            text = boot(args, log, work/(firmware+'.stderr'))
            assert 'Locale: it-IT' in text, text
            print(f'PASS: {firmware} filesystem module + plain INI override + BusyBox', flush=True)

        data, disk = work/'data.img', work/'boot.img'
        with data.open('wb') as stream:
            stream.truncate(16*1024*1024)
        subprocess.run(['mkfs.fat', '-F', '16', str(data)], check=True, stdout=subprocess.DEVNULL)
        original = data.read_bytes()
        shutil.copyfile(ROOT/'bazel-bin/boot_disk.bin', disk)
        subprocess.run(['python3', str(ROOT/'tools/vm_mount_config.py'),
                        '--boot-image', str(disk), '--data-image', str(data)], check=True)
        assert data.read_bytes() == original, 'VM profile helper modified the data image'
        generated = subprocess.check_output(['mtype', '-i', str(disk)+'@@1048576',
                                             '::RETROOS/RETROOS.INI']).decode()
        assert 'source=UUID=' in generated and 'drive=C' in generated
        assert 'source=bundle' not in generated
        config = work/'RETROOS.INI'
        config.write_text(generated.replace('[environment]', '[environment]\nTEST=/bin/busybox test -s /bin/rc'))
        subprocess.run(['mcopy', '-o', '-i', str(disk)+'@@1048576', str(config),
                        '::RETROOS/RETROOS.INI'], check=True)
        log = work/'vm.log'
        text = boot(qemu(log) + ['-drive', f'file={disk},format=raw,snapshot=on',
                                '-drive', f'file={data},format=raw',
                                '-device', f'VGA,romfile={ROOT}/third_party/vgabios/vgabios-stdvga.bin'],
                    log, work/'vm.stderr')
        assert 'Mount: data -> /home/retroos (rw)' in text and 'starting a RAM session' not in text, text
        print('PASS: generated VM UUID profile and /bin/rc resolves to bundled executable', flush=True)

        # A user's persistent app mount must also be selected by /bin/rc.
        subprocess.run(['mmd', '-i', str(data), '::CUSTOMRC'], check=True)
        marker = work/'RC.EXE'
        marker.write_text('RC-OVERRIDE')
        subprocess.run(['mcopy', '-i', str(data), str(marker), '::CUSTOMRC/RC.EXE'], check=True)
        from boot_fixture import volumes
        ident = volumes(data)[0][1]
        custom = generated.replace('[environment]', '[environment]\nTEST=/bin/busybox grep -q RC-OVERRIDE /bin/rc')
        custom += (f'[mount "rc"]\nsource=UUID={ident}\nsubdir=/CUSTOMRC\n'
                   'path=/home/retroos/RC\naccess=rw\n')
        config.write_text(custom)
        subprocess.run(['mcopy', '-o', '-i', str(disk)+'@@1048576', str(config),
                        '::RETROOS/RETROOS.INI'], check=True)
        log = work/'custom-app.log'
        text = boot(qemu(log) + ['-drive', f'file={disk},format=raw,snapshot=on',
                                '-drive', f'file={data},format=raw,snapshot=on',
                                '-device', f'VGA,romfile={ROOT}/third_party/vgabios/vgabios-stdvga.bin'],
                    log, work/'custom-app.stderr')
        assert 'Mount: rc -> /home/retroos/RC (rw)' in text, text
        print('PASS: /bin/rc follows an explicit persistent application mount', flush=True)



if __name__ == '__main__':
    main()
