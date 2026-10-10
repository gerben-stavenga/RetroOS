#!/usr/bin/env python3
"""Boot fixture helpers and unified INI composition checks."""
import hashlib
import pathlib
import shutil
import subprocess
import tempfile
import time
import uuid

ROOT = pathlib.Path(__file__).resolve().parent.parent

def run(*args, **kwargs):
    return subprocess.run(list(map(str, args)), cwd=ROOT, check=True, **kwargs)

def file(tree, name, data):
    path = tree / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

def image(work, name, tree, kind, esp=False, size_mb=32, serial=None):
    path = work / (name + '.img')
    with path.open('wb') as f:
        f.truncate(size_mb * 1024 * 1024)
    if kind == 'ext4':
        for entry in [tree, *tree.rglob('*')]:
            entry.chmod(0o755 if entry.is_dir() else 0o644)
        run('mkfs.ext4', '-q', '-F', '-b', '4096', '-d', tree, path)
    else:
        run('mkfs.fat', '-F', '16', *(['-i', serial] if serial else []), path,
            stdout=subprocess.DEVNULL)
        for entry in tree.iterdir():
            run('mcopy', '-s', '-i', path, entry, '::/')
    if esp:
        return partition_image(work, name, path, 'dos', 'ef')
    return path


def partition_image(work, name, volume, table, partition_type):
    """Wrap a filesystem in a real partition table without privileged mounts."""
    disk = work / (name + '-partitioned.img')
    size = volume.stat().st_size
    with disk.open('wb') as stream:
        stream.truncate(size + 2 * 1024 * 1024)
    run('sfdisk', disk, input=f'label: {table}\nstart=2048,size={size // 512},type={partition_type}\n',
        text=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with disk.open('r+b') as stream, volume.open('rb') as source:
        stream.seek(1024 * 1024)
        shutil.copyfileobj(source, stream)
    return disk


def boot(work, name, module, disks, protected=False, extra_args="", config=None):
    tree = work / name
    grub = tree / 'boot/grub'
    grub.mkdir(parents=True)
    shutil.copyfile(ROOT / 'bazel-bin/kernel/kernel.elf', tree / 'boot/kernel.elf')
    cmd = ['set timeout=0', 'menuentry "probe" {',
           'multiboot2 /boot/kernel.elf' + (' ram-overlay' if protected else '') + ' ' + extra_args]
    if module:
        shutil.copyfile(module, tree / 'boot/root.img')
        cmd.append('module2 /boot/root.img retroos.mount=/')
    if config is None:
        config = ('[bundle]\nsource=module\nsubdir=/home/retroos\n'
                  '[mount "session"]\nsource=bundle\npath=/home/retroos\ndrive=C\naccess=ram\n')
    (tree / 'boot/BOOT.INI').write_text(config)
    cmd.append('module2 /boot/BOOT.INI retroos.config=boot')
    cmd += ['boot', '}']
    (grub / 'grub.cfg').write_text('\n'.join(cmd) + '\n')
    iso = work / (name + '.iso')
    run('grub-mkrescue', '-o', iso, tree, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    log = work / (name + '.log')
    args = ['qemu-system-i386', '-m', '256', '-cpu', 'pentium3', '-cdrom', str(iso),
            '-boot', 'order=d', '-display', 'none', '-no-reboot', '-debugcon', 'file:' + str(log),
            '-fw_cfg', 'name=opt/cmdline,string=RETROOS/PROBE.COM']
    for index, disk in enumerate(disks):
        args += ['-drive', f'file={disk},format=raw,if=ide,index={index}']
    process = subprocess.Popen(args, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline and process.poll() is None:
            text = log.read_text(errors='replace') if log.exists() else ''
            if any(marker in text for marker in ['COMPOSITION-OK', 'COMPOSITION-FAIL', 'PANIC']):
                break
            time.sleep(.1)
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=5)
    text = log.read_text(errors='replace')
    if 'COMPOSITION-OK' not in text or 'PANIC' in text:
        raise AssertionError(name + '\n' + text)
    print('PASS:', name, flush=True)
    return text

def main():
    # Composition is now explicit INI policy. Exercise its boot transports
    # and storage semantics rather than the retired automatic CONFIG overlay.
    from boot_config import main as boot_configuration
    from mount_config import main as storage_configuration
    boot_configuration()
    storage_configuration()


if __name__ == '__main__':
    main()
