#!/usr/bin/env python3
"""Attempt a Bazel build inside QEMU/KVM running RetroOS, retaining diagnostics.

The source and installed Linux tools are shared read-only over SMB. Guest
outputs, Bazel installation/cache and temporary files use a separate writable
home. The launcher's host build only prepares the boot image.
"""
import argparse
import json
import os
import re
from pathlib import Path
import shlex
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
JVM_DEFAULTS = ['-Xmx512m', '-XX:CompressedClassSpaceSize=64m',
                '-XX:ReservedCodeCacheSize=64m']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target', nargs='?', default='//kernel:kernel')
    parser.add_argument('--bazel', type=Path, help='Native Linux Bazel executable')
    parser.add_argument('--install-base', type=Path, help='Use an already extracted Bazel runtime')
    parser.add_argument('--jvm-arg', action='append', default=[], help='Pass a host JVM argument to Bazel')
    parser.add_argument('--bazel-command', choices=('build', 'version', 'info'), default='build')
    parser.add_argument('--bazel-arg', action='append', default=[], help='Pass a Bazel command argument')
    parser.add_argument('--workspace', type=Path, default=ROOT, help='Guest-visible workspace on the shared host root')
    parser.add_argument('--env', action='append', default=[], metavar='NAME=VALUE', help='Set a guest environment variable')
    parser.add_argument('--reuse-repositories', type=Path,
                        help='Read already-extracted repositories from a host Bazel external directory')
    parser.add_argument('--work-dir', type=Path, default=ROOT / 'build/ci/self-build',
                        help='Private guest home and diagnostics directory')
    parser.add_argument('--timeout', type=int, default=14400)
    args = parser.parse_args()
    # Fit the current 3 GiB user address space.
    # Explicit environment/JVM arguments follow these defaults and override them.
    exports = ['export MALLOC_ARENA_MAX=2\n']
    for setting in args.env:
        name, separator, value = setting.partition('=')
        if not separator or not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', name):
            parser.error('--env requires NAME=VALUE')
        exports.append('export ' + name + '=' + shlex.quote(value) + '\n')
    binary = args.bazel
    if binary is None:
        version = (ROOT / '.bazelversion').read_text().strip()
        cache = Path.home() / '.cache/bazelisk/downloads'
        digest = (cache / 'metadata/bazelbuild' / f'bazel-{version}-linux-x86_64').read_text().strip()
        binary = cache / 'sha256' / digest / 'bin/bazel'
    binary = binary.resolve(strict=True)
    install_base = str(args.install_base.resolve(strict=True)) if args.install_base else '/home/retroos/bazel-install'
    work = args.work_dir.resolve()
    home = work / 'c'
    cache = 'cache-reused' if args.reuse_repositories else 'cache'
    for child in ('RETROOS', 'TEMP', 'out', cache):
        (home / child).mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / 'etc/RETROOS.INI', home / 'RETROOS/RETROOS.INI')
    startup_args = []
    if args.reuse_repositories:
        external = args.reuse_repositories.resolve(strict=True)
        overrides = []
        for repository in sorted(external.iterdir()):
            if repository.name == 'bazel_tools' or repository.name.startswith('local_config_'):
                continue
            if repository.is_dir() and any((repository / name).is_file() for name in ('BUILD', 'BUILD.bazel')):
                value = repository.name + '=' + str(repository)
                overrides.append('common --override_repository=' + shlex.quote(value) + '\n')
        (home / 'repositories.bazelrc').write_text(''.join(overrides))
        startup_args.append('--bazelrc=/home/retroos/repositories.bazelrc')
        print(f'Reusing {len(overrides)} extracted repositories read-only; guest outputs remain private', flush=True)
    command = [str(binary), '--batch', '--nosystem_rc', '--nohome_rc', '--output_user_root=/home/retroos/' + cache,
               '--install_base=' + install_base, *startup_args,
               *['--host_jvm_args=' + arg for arg in JVM_DEFAULTS + args.jvm_arg], args.bazel_command]
    if args.bazel_command == 'build':
        command += ['--spawn_strategy=standalone', '--genrule_strategy=standalone',
                    '--jobs=1', '--loading_phase_threads=1', '--legacy_globbing_threads=1', '--symlink_prefix=/home/retroos/out/bazel-', *args.bazel_arg, args.target]
    else:
        command += args.bazel_arg
    (home / 'run.sh').write_text(
        'cd ' + shlex.quote(str(args.workspace.resolve(strict=True))) + ' || exit 1\n' +
        ''.join(exports) +
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
