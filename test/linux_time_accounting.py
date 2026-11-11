#!/usr/bin/env python3
"""Account for one fork/exec/wait workload on ext4 or SMB, with stdin gates."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import time
import native_program_profile
from linux_smb_symlink import ROOT


def run(backend, workload, bridge, resident=False, host_tools=False, metal_devices=False, reuse_fixture=False, inode_size=256, direct_io=False, from_dn=False):
    work = ROOT / 'build/ci/time-accounting' / (backend + '-' + workload
        + ('-resident' if resident else '') + ('-host-tools' if host_tools else ''))
    home = work / 'c'
    (home / 'RETROOS').mkdir(parents=True, exist_ok=True)
    (home / 'TEMP').mkdir(exist_ok=True)
    if from_dn:
        shutil.copytree(ROOT/'boot-bundle/dn',home/'DN',dirs_exist_ok=True)
        subprocess.run(['mcopy','-o','-i',str(ROOT/'bazel-bin/boot_disk.bin')+'@@1048576',
                        '::RETROOS/COMMAND.COM',str(home/'RETROOS/COMMAND.COM')],check=True)
        (home/'run.bat').write_bytes(b'C:\\RETROOS\\SHELL.ELF\r\n')
    shutil.copyfile(ROOT / 'etc/RETROOS.INI', home / 'RETROOS/RETROOS.INI')
    subprocess.run(['gcc', '-m64', '-nostdlib', '-static', '-no-pie', '-fno-pie',
                    '-fno-stack-protector', '-fno-builtin', '-O2',
                    str(ROOT / 'test/linux_program_timer.c'), '-o', str(home / 'timer')], check=True)
    (home / 'hello.c').write_text('#include <stdio.h>\nint main(void){puts("BUILD_PROFILE_PASS");return 0;}\n')
    command = ['/usr/bin/python3', '-c', 'import pathlib,sqlite3,subprocess;print("PYTHON_PASS")']
    if workload == 'build':
        command = ['/bin/sh', '-c', '/usr/bin/gcc -O2 -c /home/retroos/hello.c -o /home/retroos/hello.o && /usr/bin/gcc /home/retroos/hello.o -o /home/retroos/hello && /home/retroos/hello']
    elif workload == 'temp-build':
        command = ['/bin/sh', '-c', '/usr/bin/gcc -O2 /home/retroos/hello.c -o /home/retroos/hello && /home/retroos/hello']
    elif workload == 'login':
        command = ['/bin/bash', '-lc', 'true']
    elif workload == 'flatpak':
        command = ['/bin/bash', '--noprofile', '--norc', '-c', '. /etc/profile.d/flatpak.sh']
    elif workload == 'lookup':
        command = ['/bin/bash', '--noprofile', '--norc', '-c', 'command -v flatpak']
    elif workload == 'python-build':
        (home / 'build.py').write_text('''import subprocess, time, json, sys
from pathlib import Path
d = Path('/home/retroos')
for name, argv in [
    ('compile', ['/usr/bin/gcc', '-O2', '-c', str(d/'hello.c'), '-o', str(d/'hello.o')]),
    ('link', ['/usr/bin/gcc', str(d/'hello.o'), '-o', str(d/'hello')]),
    ('run', [str(d/'hello')])]:
    start = time.monotonic()
    p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print(json.dumps(dict(name=name, seconds=time.monotonic()-start, returncode=p.returncode)), flush=True, file=sys.stderr)
    assert p.returncode == 0, p.stderr
print('PYTHON_BUILD_PASS',flush=True,file=sys.stderr)
''')
        command = ['/usr/bin/python3', '/home/retroos/build.py']
    timed = ['/home/retroos/timer', '--profile', workload, *command]
    binaries = []
    if resident:
        binary = (Path.home()/'.codex/packages/app-server-daemon/current/bin/codex-code-mode-host').resolve(strict=True)
        binaries.append(str(binary))
        shutil.copyfile(ROOT/'test/linux_code_mode_stress_probe.py', home/'stress.py')
        timed = ['/usr/bin/python3', '/home/retroos/stress.py', str(binary), '--sessions', '24', '--after-command', *timed]
    (home / 'run.sh').write_text('export HOME=/home/retroos TMPDIR=/home/retroos/TEMP MALLOC_ARENA_MAX=2\n'
        + shlex.join(timed) + '\nexit $?\n')
    desktop = workload in ('login', 'flatpak', 'lookup')
    if desktop:
        binaries += ['/bin/bash', '/usr/bin/flatpak', '/usr/bin/locale-check']
    image = work / 'native-root.ext4'
    if reuse_fixture:
        if not image.is_file() or not (work/'native-root/home/retroos').is_dir():
            raise RuntimeError('No prepared fixture to reuse: ' + str(work))
        shutil.copytree(home, work/'native-root/home/retroos', dirs_exist_ok=True)
    else:
        image = native_program_profile.prepare(work, home, False, extra_binaries=binaries,
            image_bytes=(8 if host_tools else 2) * 1024**3)
    if host_tools and not reuse_fixture:
        # Copy public system tools and libraries, retaining their real symlinks
        # and contents. The guest never mounts the live host filesystem.
        root = work / 'native-root'
        for directory in ('/usr/bin', '/usr/lib/x86_64-linux-gnu'):
            subprocess.run(['cp', '-a', directory + '/.', str(root / directory.lstrip('/')) + '/'], check=True)
    if desktop and not reuse_fixture:
        root = work / 'native-root'
        for source in [Path('/etc/profile'), *Path('/etc/profile.d').glob('*.sh')]:
            destination = root / source.relative_to('/')
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
        # Reproduce the host's directory sizes without copying unrelated programs
        # or private user state. Real test tools and their libraries stay intact.
        for directory in ('/usr/bin', '/usr/local/bin', '/usr/sbin', '/usr/lib', '/usr/lib/x86_64-linux-gnu'):
            destination = root / directory.lstrip('/')
            destination.mkdir(parents=True, exist_ok=True)
            for source in Path(directory).iterdir():
                target = destination / source.name
                if not target.exists() and not target.is_symlink():
                    if source.is_dir():
                        target.mkdir()
                    else:
                        target.touch()
    if desktop or host_tools or reuse_fixture:
        subprocess.run(['mkfs.ext4', '-q', '-F', '-I', str(inode_size),
                        '-d', str(work / 'native-root'), str(image)], check=True)
    (work / 'profile.json').write_text(json.dumps({'root': str(work / 'native-root'), 'c_root': str(home)}))
    env = os.environ.copy()
    env['RETROOS_PREBUILT'] = '1'
    env.pop('RETROOS_DATA_IMAGE', None)
    env['RETROOS_QEMU_LIVE_PROFILE'] = str(work / 'profile.json')
    command = [str(ROOT / 'run.sh'), 'qemu', '--kvm', '--headless', '--sound', 'hda' if metal_devices else 'none']
    if backend == 'ext4':
        command += ['--net', 'virtio' if metal_devices else 'none', '--hd', 'nvme', '--data-image', str(image)]
    startup = '/home/retroos/DN/DN.COM' if from_dn else '/home/retroos/RETROOS/SHELL.ELF /home/retroos/run.sh'
    command += ['--cmd', startup, '--', '-m', '32768', '-smp', '6']
    command += ['-qmp', f'unix:{work}/qmp.sock,server=on,wait=off']
    if metal_devices:
        command += ['-global', 'bochs-display.xres=2560', '-global', 'bochs-display.yres=1600',
                    '-audiodev', 'none,id=diagnostic-audio', '-global', 'hda-duplex.audiodev=diagnostic-audio']
    if direct_io:
        if backend != 'ext4':
            raise ValueError('Direct I/O requires the private ext4 disk')
        command += ['-set', 'drive.data.cache=none']
    suffix = '' if inode_size == 256 else '-inode' + str(inode_size)
    suffix += ('-direct' if direct_io else '') + ('-devices' if metal_devices else '') + ('-dn' if from_dn else '')
    log = work / ('klog' + suffix + '.txt')
    control = None
    dn_shell_submitted = False
    dn_diagnostic_at = 0
    with log.open('w') as output:
        process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=output, stderr=subprocess.STDOUT)
        try:
            end = time.monotonic() + 180
            while time.monotonic() < end:
                text = log.read_text(errors='replace')
                if process.poll() is not None:
                    raise RuntimeError('Guest exited before measurement: ' + str(log))
                match = re.search(r'MCP control: (\S+)', text)
                if from_dn and match and 'event_loop entered' in text and control is None:
                    control = bridge.SerialControl(None,match.group(1))
                    time.sleep(3)
                    control.request('texthex '+b'C:\\RETROOS\\COMMAND.COM /B C:\\run.bat'.hex())
                    control.request('key enter')
                    control.request('profile reset')
                    control.request('profile on')
                if from_dn and control and not dn_shell_submitted and 'child tid=3, parent tid=2' in text:
                    # DOS-to-ELF launch currently drops the DOS argument tail;
                    # use the interactive shell, as the physical run does.
                    time.sleep(8)
                    control.request('texthex '+b'/bin/sh /home/retroos/run.sh'.hex())
                    control.request('key enter')
                    dn_shell_submitted = True
                if from_dn and control and time.monotonic() >= dn_diagnostic_at:
                    sample = {name: control.request(name, timeout=20)
                        for name in ('profile totals','profile io','profile top')}
                    with (work/'dn-startup-samples.jsonl').open('a') as samples:
                        samples.write(json.dumps(sample)+'\n')
                    if dn_shell_submitted:
                        control.request('debug dump')
                    dn_diagnostic_at = time.monotonic()+10
                if match and 'PROFILE_READY ' + workload in text:
                    if control is None:
                        control = bridge.SerialControl(None, match.group(1))
                    break
                time.sleep(.02)
            else:
                raise RuntimeError('Guest never reached start gate: ' + str(log))
            control.request('profile on')
            control.request('profile reset')
            control.request('key enter')
            while time.monotonic() < end:
                text = log.read_text(errors='replace')
                match = re.search(r'PROFILE_DONE ' + workload + r' (\d+)ns', text)
                if match:
                    elapsed_ns = int(match.group(1))
                    break
                if process.poll() is not None:
                    raise RuntimeError('Guest exited during workload: ' + str(log))
                time.sleep(.005)
            else:
                raise RuntimeError('Workload timed out: ' + str(log))
            result = {'backend': backend, 'workload': workload, 'workload_ns': elapsed_ns,
                      'resident_code_mode': resident, 'host_tools': host_tools, 'metal_devices': metal_devices,
                      'inode_size': inode_size}
            result['direct_io'] = direct_io
            result['from_dn'] = from_dn
            for name in ('profile totals', 'profile execution', 'profile io', 'profile top'):
                result[name] = control.request(name, timeout=30)
            control.request('profile off')
            control.request('key enter')
            if from_dn:
                time.sleep(.2)
                process.terminate()
            process.wait(timeout=30)
            result['guest_exit_code'] = process.returncode
            totals = result['profile totals']
            total_cycles = sum(totals['cycles'].values())
            assert total_cycles and totals['elapsed_ns'] >= elapsed_ns
            result['accounted_ns'] = {name: round(cycles * totals['elapsed_ns'] / total_cycles)
                for name, cycles in totals['cycles'].items()}
            result['boundary_overhead_ns'] = totals['elapsed_ns'] - elapsed_ns
            (work / ('report' + suffix + '.json')).write_text(json.dumps(result, indent=2) + '\n')
            print(json.dumps({'backend': backend, 'workload': workload, 'workload_ms': elapsed_ns / 1e6,
                'accounted_ms': {k: round(v / 1e6, 3) for k, v in result['accounted_ns'].items()},
                'boundary_overhead_ms': result['boundary_overhead_ns'] / 1e6}), flush=True)
            if not from_dn:
                assert process.returncode == 0 and '[mem] exit tid=1 code=0' in log.read_text(), str(log)
        finally:
            if control:
                control.close()
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=15)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backend', choices=('ext4', 'smb', 'both'), default='both')
    parser.add_argument('--workload', choices=('build', 'python', 'temp-build', 'login', 'flatpak', 'lookup', 'python-build'), default='build')
    parser.add_argument('--resident-code-mode', action='store_true')
    parser.add_argument('--host-tools', action='store_true', help='Copy full host /usr/bin and architecture library directory into private ext4')
    parser.add_argument('--metal-devices', action='store_true', help='Exercise a 2560x1600 framebuffer, HDA audio, and a virtio network')
    parser.add_argument('--reuse-fixture', action='store_true', help='Rebuild the private image from its existing prepared root')
    parser.add_argument('--inode-size', choices=(256, 512, 1024, 2048, 4096), type=int, default=256,
                        help='Spread directory metadata over more pages using a valid ext4 inode size')
    parser.add_argument('--direct-io', action='store_true', help='Bypass the host page cache for the private QEMU data disk')
    parser.add_argument('--from-dn', action='store_true', help='Launch the benchmark through real DN and its DOS batch helper')
    args = parser.parse_args()
    if os.environ.get('RETROOS_PREBUILT') != '1':
        subprocess.run(['bazelisk', 'build', '//:boot_disk'], cwd=ROOT, check=True)
    spec = importlib.util.spec_from_file_location('serial_bridge', ROOT / 'tools/86box_mcp.py')
    bridge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bridge)
    for backend in ('ext4', 'smb') if args.backend == 'both' else (args.backend,):
        run(backend, args.workload, bridge, args.resident_code_mode, args.host_tools,
            args.metal_devices, args.reuse_fixture, args.inode_size, args.direct_io, args.from_dn)


if __name__ == '__main__':
    main()
