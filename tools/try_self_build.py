#!/usr/bin/env python3
"""Attempt a Bazel build inside QEMU/KVM running RetroOS, retaining diagnostics.

The source and installed Linux tools are shared read-only over SMB. Guest
outputs, Bazel installation/cache and temporary files use a separate writable
home. The launcher's host build only prepares the boot image.
"""
import argparse
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JVM_DEFAULTS = ['-Xmx512m', '-XX:CompressedClassSpaceSize=64m',
                '-XX:ReservedCodeCacheSize=64m', '-Djava.io.tmpdir=/home/retroos/build-tmp']


def compiler_libraries(work, external):
    directories = {repo / 'lib' for repo in external.glob('*nightly_tools')
                   if any((repo / 'lib').glob('librustc_driver*.so'))}
    directories.update(repo / 'rustc/lib' for repo in external.glob('*rust_toolchain*')
                       if any((repo / 'rustc/lib').glob('librustc_driver*.so')))
    directories = sorted(directories)
    if not directories:
        raise ValueError('No extracted Rust compiler libraries found')
    def manifest(directory):
        result = {}
        for path in sorted(directory.rglob('*')):
            kind = path.lstat().st_mode
            if path.is_symlink(): value = str(path.readlink())
            elif path.is_file():
                with path.open('rb') as stream: value = hashlib.file_digest(stream, 'sha256').hexdigest()
            else: value = ''
            result[str(path.relative_to(directory))] = [kind, value]
        return result
    expected = [manifest(directory) for directory in directories]
    identity = hashlib.sha256(json.dumps(expected, sort_keys=True).encode()).hexdigest()[:16]
    image = work / f'compiler-libs-{identity}.ext4'
    marker = image.with_suffix('.json')
    if image.exists():
        if not marker.exists() or json.loads(marker.read_text()) != expected:
            raise ValueError('Compiler library image is stale; use a fresh work directory')
    else:
        # Keep each toolchain tree intact, sharing identical file bytes only
        # inside the disposable staging tree. Never hard-link host SDK files.
        copies = {}
        def copy(source, destination):
            meta = Path(source).stat()
            with open(source, 'rb') as stream: digest = hashlib.file_digest(stream, 'sha256').hexdigest()
            key = (meta.st_mode, meta.st_mtime_ns, digest)
            if key in copies: os.link(copies[key], destination)
            else:
                shutil.copy2(source, destination)
                copies[key] = destination
            return destination
        with tempfile.TemporaryDirectory(prefix='retroos-compiler-libs-') as directory:
            staging = Path(directory)
            for index, source in enumerate(directories):
                shutil.copytree(source, staging / f'lib{index}', symlinks=True, copy_function=copy)
            with image.open('wb') as output: output.truncate(4 * 1024**3)
            subprocess.run(['mkfs.ext4', '-q', '-F', '-d', str(staging), str(image)], check=True)
        marker.write_text(json.dumps(expected, indent=2))
    return image, [{'path': str(directory), 'subdir': f'/lib{index}'}
                   for index, directory in enumerate(directories)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target', nargs='?', default='//kernel:kernel')
    parser.add_argument('--bazel', type=Path, help='Native Linux Bazel executable')
    parser.add_argument('--install-base', type=Path, help='Use an already extracted Bazel runtime')
    parser.add_argument('--jvm-arg', action='append', default=[], help='Pass a host JVM argument to Bazel')
    parser.add_argument('--bazel-command', choices=('build', 'version', 'info'), default='build')
    parser.add_argument('--trace-processes', action='store_true', help='Trace guest process creation, exec, waits and signals')
    parser.add_argument('--clean', action='store_true', help='Clean private guest Bazel outputs before building')
    parser.add_argument('--bazel-arg', action='append', default=[], help='Pass a Bazel command argument')
    parser.add_argument('--workspace', type=Path, default=ROOT, help='Guest-visible workspace on the shared host root')
    parser.add_argument('--env', action='append', default=[], metavar='NAME=VALUE', help='Set a guest environment variable')
    parser.add_argument('--reuse-repositories', type=Path,
                        help='Read already-extracted repositories from a host Bazel external directory')
    parser.add_argument('--work-dir', type=Path, default=ROOT / 'build/ci/self-build',
                        help='Private guest home and diagnostics directory')
    parser.add_argument('--home-mib', type=int, default=4096, help='Native home filesystem size in MiB')
    parser.add_argument('--native-home', action='store_true', help='Keep guest outputs on a private native ext4 image')
    parser.add_argument('--reuse-native-home', action='store_true', help='Resume an existing private native home image')
    parser.add_argument('--native-compiler-libs', action='store_true', help='Read installed Rust compiler libraries from a private native ext4 image')
    parser.add_argument('--cpus', type=int, default=5, help='QEMU logical processors (core 1 is reserved for media)')
    parser.add_argument('--memory-mib', type=int, default=4096, help='QEMU guest RAM in MiB')
    parser.add_argument('--timeout', type=int, default=14400)
    parser.add_argument('--gdb-socket', type=Path, help='Expose QEMU GDB control on a private Unix socket')
    args = parser.parse_args()
    if args.native_compiler_libs and (not args.native_home or not args.reuse_repositories):
        parser.error('--native-compiler-libs requires --native-home and --reuse-repositories')
    if args.reuse_native_home and not args.native_home:
        parser.error('--reuse-native-home requires --native-home')
    # Fit the current 3 GiB user address space.
    # Explicit environment/JVM arguments follow these defaults and override them.
    # TEMP and /tmp are session RAM overlays with a 32 MiB capacity. Compiler
    # source extraction needs the writable home filesystem instead.
    exports = ['export MALLOC_ARENA_MAX=2\n', 'export TMPDIR=/home/retroos/build-tmp\n']
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
    work.mkdir(parents=True, exist_ok=True)
    fixture_lock = (work / 'fixture.lock').open('a')
    try:
        fcntl.flock(fixture_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        parser.error('this self-build fixture is already running')
    home = work / 'c'
    cache = 'cache-reused' if args.reuse_repositories else 'cache'
    for child in ('RETROOS', 'TEMP', 'build-tmp', 'out', cache):
        (home / child).mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / 'etc/RETROOS.INI', home / 'RETROOS/RETROOS.INI')
    startup_args = []
    if args.reuse_repositories:
        external = args.reuse_repositories.resolve(strict=True)
        overrides = []
        for repository in sorted(external.iterdir()):
            if repository.name == 'bazel_tools' or repository.name.startswith('local_config_'):
                continue
            if repository.is_dir() and any((repository / name).is_file() for name in ('BUILD', 'BUILD.bazel', 'WORKSPACE', 'WORKSPACE.bazel', 'MODULE.bazel')):
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
                    '--action_env=TMPDIR=/home/retroos/build-tmp',
                    f'--jobs={max(1, args.cpus - 1)}', '--loading_phase_threads=1', '--legacy_globbing_threads=1', '--symlink_prefix=/home/retroos/out/bazel-', *args.bazel_arg, args.target]
    else:
        command += args.bazel_arg
    cleaning = ''
    if args.clean:
        if args.bazel_command != 'build': parser.error('--clean requires --bazel-command=build')
        cleaning = shlex.join(command[:command.index('build')] + ['clean']) + ' > /home/retroos/clean.out 2> /home/retroos/clean.err || exit $?\n'
    tracing = ''
    if args.trace_processes:
        code = f"from importlib.machinery import SourceFileLoader; b=SourceFileLoader('retroos_bridge', {str(ROOT / 'tools/86box_mcp.py')!r}).load_module(); c=b.LocalControl(); print(c.request('trace process')); c.close()"
        tracing = shlex.join(['/usr/bin/python3', '-c', code]) + '\n'
    (home / 'run.sh').write_text(
        'cd ' + shlex.quote(str(args.workspace.resolve(strict=True))) + ' || exit 1\n' +
        ''.join(exports) + tracing +
        "printf '' > /home/retroos/build.out\nprintf '' > /home/retroos/build.err\nprintf '' > /home/retroos/compilers.log\n" + cleaning +
        shlex.join(command) + ' > /home/retroos/build.out 2> /home/retroos/build.err\n'
        'result=$?\nprintf "%s\\n" "$result" > /home/retroos/build.status\n'
        'exit "$result"\n')
    for name in ('build.out', 'build.err', 'build.status'):
        (home / name).unlink(missing_ok=True)
    profile = work / 'profile.json'
    settings = {'root': '/', 'c_root': str(home)}
    native_image = work / 'home.ext4'
    if args.native_home:
        if args.reuse_native_home:
            if not native_image.is_file(): parser.error('native home image is missing')
            with (work / 'e2fsck.log').open('w') as output:
                checked = subprocess.run(['e2fsck', '-p', str(native_image)], stdout=output, stderr=subprocess.STDOUT)
            if checked.returncode not in (0, 1, 2):
                parser.error('native image requires repair; see e2fsck.log')
            subprocess.run(['debugfs', '-w', '-R', 'mkdir /home/retroos/build-tmp', str(native_image)], capture_output=True, check=True)
            for field, value in [('uid', os.getuid()), ('gid', os.getgid())]:
                subprocess.run(['debugfs', '-w', '-R', f'set_inode_field /home/retroos/build-tmp {field} {value}', str(native_image)], capture_output=True, check=True)
            for name in ('run.sh', 'repositories.bazelrc'):
                if not (home / name).exists(): continue
                subprocess.run(['debugfs', '-w', '-R', f'rm /home/retroos/{name}', str(native_image)], capture_output=True, check=True)
                subprocess.run(['debugfs', '-w', '-R', f'write {json.dumps(str(home/name))} /home/retroos/{name}', str(native_image)], capture_output=True, check=True)
        else:
            if native_image.exists(): parser.error('--native-home requires a fresh work directory (or --reuse-native-home)')
            with tempfile.TemporaryDirectory(prefix='retroos-self-build-home-') as directory:
                staging = Path(directory)
                shutil.copytree(home, staging / 'home/retroos', symlinks=True)
                with native_image.open('wb') as image:
                    image.truncate(args.home_mib * 1024**2)
                subprocess.run(['mkfs.ext4', '-q', '-F', '-d', str(staging), str(native_image)], check=True)
        subprocess.run(['debugfs', '-w', '-R', 'rm /home/retroos/build.status', str(native_image)], capture_output=True)
        settings['native_home_image'] = str(native_image)
    compiler_image = None
    if args.native_compiler_libs:
        compiler_image, paths = compiler_libraries(work, args.reuse_repositories.resolve(strict=True))
        settings['native_tool_image'] = str(compiler_image)
        settings['native_tool_paths'] = paths
        print('Compiler libraries on native ext4; source/toolchain bytes unchanged', flush=True)
    profile.write_text(json.dumps(settings))
    env = os.environ.copy()
    env.pop('RETROOS_DATA_IMAGE', None)
    env['RETROOS_QEMU_LIVE_PROFILE'] = str(profile)
    timed_out = False
    with (work / 'klog.txt').open('w') as log:
        qmp = work / 'qmp.sock'
        qmp.unlink(missing_ok=True)
        qemu_args = ['-m', str(args.memory_mib), '-smp', str(args.cpus),
                     '-name', 'retroos-self-build,debug-threads=on',
                     '-qmp', f'unix:{qmp},server=on,wait=off']
        if args.gdb_socket:
            qemu_args += ['-gdb', f'unix:{args.gdb_socket.resolve()},server=on,wait=off']
        if args.native_home:
            qemu_args += ['-drive', f'file={native_image},format=raw,if=none,id=selfbuildhome',
                          '-device', 'nvme,drive=selfbuildhome,serial=SELFBUILD']
        if compiler_image:
            qemu_args += ['-drive', f'file={compiler_image},format=raw,readonly=on,if=none,id=selfbuildtools',
                          '-device', 'nvme,drive=selfbuildtools,serial=COMPILER']
        process = subprocess.Popen([str(ROOT / 'run.sh'), 'qemu', '--kvm',
            '--headless', '--sound', 'none', '--cmd',
            '/home/retroos/RETROOS/SHELL.ELF /home/retroos/run.sh', '--', *qemu_args],
            cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
        try:
            process.wait(timeout=args.timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=15)
    if args.native_home:
        for name in ('build.out', 'build.err', 'build.status', 'clean.out', 'clean.err', 'compilers.log', 'build-profile.json', 'build-events.json'):
            subprocess.run(['debugfs', '-R', f'dump /home/retroos/{name} {home/name}',
                            str(native_image)], capture_output=True)
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
