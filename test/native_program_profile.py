"""Private native-ext4 tool root for the program startup/build profiler."""
from pathlib import Path
import os
import re
import shutil
import subprocess
from linux_smb_symlink import ROOT


def prepare(work, home, codex, extra_binaries=(), image_bytes=2 * 1024 * 1024 * 1024,
            allocation_fill_bytes=0):
    root = work / 'native-root'
    root.mkdir(exist_ok=True)
    for name in ('bin', 'lib', 'lib64'):
        (root / 'usr' / name).mkdir(parents=True, exist_ok=True)
        if not (root / name).exists():
            (root / name).symlink_to('usr/' + name)
    copied = set()

    def copy_file(source):
        source = Path(source)
        if str(source) in copied or not source.is_file():
            return
        copied.add(str(source))
        destination = root / str(source).lstrip('/')
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists() or destination.stat().st_size != source.stat().st_size:
            shutil.copy2(source, destination)

    binaries = ['/bin/sh', '/bin/true', '/usr/bin/time', *extra_binaries]
    if codex:
        import sys
        sys.path.insert(0, str(ROOT / 'tools'))
        from setup_codex import DEFAULT_BINARY
        binaries.append(str(DEFAULT_BINARY.resolve(strict=True)))
    else:
        binaries += ['/usr/bin/python3', '/usr/bin/gcc', '/usr/bin/as', '/usr/bin/ld']
        for directory in ('/usr/include', '/usr/lib/gcc/x86_64-linux-gnu', '/usr/libexec/gcc/x86_64-linux-gnu', '/usr/lib/python3.12'):
            if not Path(directory).is_dir():
                continue
            destination = root / directory.lstrip('/')
            if not destination.exists():
                shutil.copytree(directory, destination, ignore_dangling_symlinks=True)
        for name in ('crt1.o', 'Scrt1.o', 'crti.o', 'crtn.o', 'libc.so', 'libc_nonshared.a', 'libgcc_s.so.1'):
            copy_file('/usr/lib/x86_64-linux-gnu/' + name)
        for program in ('cc1', 'collect2', 'lto-wrapper'):
            binaries.append(subprocess.check_output(['gcc', '-print-prog-name=' + program], text=True).strip())
        binaries += [str(p) for p in Path('/usr/lib/python3.12/lib-dynload').glob('*.so')]
    for binary in binaries:
        copy_file(binary)
        dependencies = subprocess.run(['ldd', binary], capture_output=True, text=True).stdout
        for dependency in re.findall(r'(/[^\s()]+)', dependencies):
            copy_file(dependency)
    copy_file('/lib64/ld-linux-x86-64.so.2')
    copy_file('/etc/ld.so.cache')
    if codex:
        copy_file('/etc/ssl/certs/ca-certificates.crt')
    destination = root / 'home/retroos'
    if destination.exists():
        # Remove only this fixture's former guest home, keeping cached tools.
        shutil.rmtree(destination)
    shutil.copytree(home, destination)
    if allocation_fill_bytes:
        (root / 'filler').write_bytes(b'')
    subprocess.run(['mcopy', '-o', '-i', str(ROOT / 'bazel-bin/boot_disk.bin') + '@@1048576',
                    '::RETROOS/SHELL.ELF', str(destination / 'RETROOS/SHELL.ELF')], check=True)
    image = work / 'native-root.ext4'
    with image.open('wb') as output:
        output.truncate(image_bytes)
    layout = ['-b', '4096', '-g', '1024', '-N', '65536', '-O', '^meta_bg,^resize_inode'] if allocation_fill_bytes else []
    subprocess.run(['mkfs.ext4', '-q', '-F', *layout, '-d', str(root), str(image)], check=True)
    if allocation_fill_bytes:
        last = allocation_fill_bytes // 4096 - 1
        subprocess.run(['debugfs', '-w', '-R', f'fallocate /filler 0 {last}', str(image)], check=True, capture_output=True)
        subprocess.run(['e2fsck', '-f', '-n', str(image)], check=True, capture_output=True)
    return image


def stage(image):
    result = subprocess.run(['debugfs', '-R', 'cat /home/retroos/stage', str(image)],
                            capture_output=True, text=True)
    return result.stdout.strip() or 'startup'


def launch(work, home, image, label, names):
    log = ROOT / 'build/ci' / (label + '.log')
    env = os.environ.copy()
    env.pop('RETROOS_DATA_IMAGE', None)
    with log.open('w') as output:
        process = subprocess.Popen([str(ROOT / 'run.sh'), 'qemu', '--kvm', '--headless',
            '--sound', 'none', '--net', 'none', '--hd', 'nvme', '--data-image', str(image),
            '--cmd', '/home/retroos/RETROOS/SHELL.ELF /home/retroos/run.sh', '--',
            '-m', '32768', '-smp', '6', '-audiodev', 'none,id=snd0',
            '-device', 'intel-hda', '-device', 'hda-duplex,audiodev=snd0'],
            cwd=ROOT, env=env, stdout=output, stderr=subprocess.STDOUT)
        try:
            process.wait(timeout=300)
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=15)
            for name in ['timings', 'stage'] + ['output-' + name for name in names] + ['errors-' + name for name in names]:
                subprocess.run(['debugfs', '-R', f'dump /home/retroos/{name} {home / name}', str(image)], capture_output=True)
    assert process.returncode == 0 and '[mem] exit tid=1 code=0' in log.read_text(), str(log)
