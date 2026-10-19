#!/usr/bin/env python3
"""Attempt a Bazel build inside QEMU/KVM running RetroOS, retaining diagnostics.

The source and installed Linux tools are shared read-only over SMB. Guest
outputs, Bazel installation/cache and temporary files use a separate writable
home. The launcher's host build only prepares the boot image.
"""
import argparse
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target', nargs='?', default='//kernel:kernel')
    parser.add_argument('--bazel', type=Path, help='Native Linux Bazel executable')
    parser.add_argument('--install-base', type=Path, help='Use an already extracted Bazel runtime')
    parser.add_argument('--jvm-arg', action='append', default=[], help='Pass a host JVM argument to Bazel')
    parser.add_argument('--timeout', type=int, default=240)
    args = parser.parse_args()
    binary = args.bazel
    if binary is None:
        version = (ROOT / '.bazelversion').read_text().strip()
        cache = Path.home() / '.cache/bazelisk/downloads'
        digest = (cache / 'metadata/bazelbuild' / f'bazel-{version}-linux-x86_64').read_text().strip()
        binary = cache / 'sha256' / digest / 'bin/bazel'
    binary = binary.resolve(strict=True)
    install_base = str(args.install_base.resolve(strict=True)) if args.install_base else '/home/retroos/bazel-install'
    work = ROOT / 'build/ci/self-build'
    home = work / 'c'
    for child in ('RETROOS', 'TEMP', 'out', 'cache'):
        (home / child).mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / 'etc/RETROOS.INI', home / 'RETROOS/RETROOS.INI')
    command = [str(binary), '--batch', '--nosystem_rc', '--nohome_rc', '--output_user_root=/home/retroos/cache',
               '--install_base=' + install_base, *['--host_jvm_args=' + arg for arg in args.jvm_arg], 'build',
               '--spawn_strategy=standalone', '--genrule_strategy=standalone',
               '--jobs=1', '--symlink_prefix=/home/retroos/out/bazel-', args.target]
    (home / 'run.sh').write_text(
        'cd ' + shlex.quote(str(ROOT)) + ' || exit 1\n' +
        shlex.join(command) + ' > /home/retroos/build.out 2> /home/retroos/build.err\n'
        'result=$?\nprintf "%s\\n" "$result" > /home/retroos/build.status\n'
        'exit "$result"\n')
    for name in ('build.out', 'build.err', 'build.status'):
        (home / name).unlink(missing_ok=True)
    profile = work / 'profile.json'
    profile.write_text(json.dumps({'root': '/', 'c_root': str(home)}))
    env = os.environ.copy()
    env.pop('RETROOS_DATA_IMAGE', None)
    env['RETROOS_QEMU_LIVE_PROFILE'] = str(profile)
    timed_out = False
    with (work / 'klog.txt').open('w') as log:
        process = subprocess.Popen([str(ROOT / 'run.sh'), 'qemu', '--kvm',
            '--headless', '--sound', 'none', '--cmd',
            '/home/retroos/RETROOS/SHELL.ELF /home/retroos/run.sh', '--', '-m', '4096'],
            cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
        try:
            process.wait(timeout=args.timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=15)
    status = home / 'build.status'
    success = not timed_out and process.returncode == 0 and status.exists() and status.read_text().strip() == '0'
    print(('PASS' if success else 'BLOCKED') + ': guest build; diagnostics: ' + str(work))
    for name in ('build.out', 'build.err'):
        path = home / name
        if path.exists():
            print(path.read_text(errors='replace')[-6000:])
    raise SystemExit(0 if success else 1)


if __name__ == '__main__':
    main()
