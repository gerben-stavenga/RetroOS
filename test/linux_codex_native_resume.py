#!/usr/bin/env python3
"""Profile real Codex startup/resume/typing using private state on native ext4.

Never submits the draft or mounts the host filesystem in the guest.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import sqlite3
import subprocess
import tempfile
import time

import native_program_profile
from linux_smb_symlink import ROOT


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-from', type=Path, default=Path.home() / '.codex')
    parser.add_argument('--resume', help='Saved thread ID or "latest" in this project; omit for a new thread')
    parser.add_argument('--picker', action='store_true', help='Measure /resume listing and selecting a session after startup; copy all saved rollouts')
    parser.add_argument('--filled', action='store_true', help='Place private state on a populated filesystem with thousands of occupied block groups')
    parser.add_argument('--kernel', type=Path, help='Compare an explicit kernel in a private UEFI boot copy (native ext4 only)')
    parser.add_argument('--label', help='Artifact directory suffix for a comparison run')
    parser.add_argument('--daemon', action='store_true')
    parser.add_argument('--full-features', action='store_true', help='Keep ordinary app/plugin startup enabled')
    parser.add_argument('--existing-skills', action='store_true', help='Copy installed skills instead of measuring their first installation')
    parser.add_argument('--timeout', type=float, default=240)
    parser.add_argument('--network', choices=('none', 'virtio'), default='virtio')
    parser.add_argument('--storage', choices=('ext4', 'smb'), default='ext4')
    parser.add_argument('--live-tools', action='store_true', help='Use the host tool tree with a private SMB guest home')
    parser.add_argument('--memory', type=int, default=32768, help='Guest RAM in MiB')
    parser.add_argument('--cpus', type=int, default=6)
    parser.add_argument('--capture-network', action='store_true', help='Capture Ethernet/IP/TCP headers only for startup timing')
    parser.add_argument('--sample-interval', type=float, default=5, help='Seconds between detailed samples; zero records readiness only')
    parser.add_argument('--no-profile', action='store_true', help='Measure readiness with kernel profiling disabled')
    parser.add_argument('--background-build', action='store_true', help='Measure a Python-launched C build while the real Codex UI remains running')
    parser.add_argument('--tools-from', type=Path, help='Copy public system tools from a previously prepared private native root')
    parser.add_argument('--direct-io', action='store_true', help='Bypass the host page cache for the private data image')
    parser.add_argument('--screen-transport', choices=('serial', 'qmp'), default='serial',
                        help='Use QEMU debugger memory reads to avoid the diagnostic screen UART cost')
    args = parser.parse_args()
    args.state_from = args.state_from.expanduser().resolve(strict=True)
    if args.storage == 'smb' and args.network == 'none':
        parser.error('SMB needs the virtio network')
    if args.live_tools and args.storage != 'smb':
        parser.error('--live-tools requires --storage smb')
    if args.storage == 'smb' and args.kernel:
        parser.error('--kernel comparison needs native ext4')
    # Finish host compilation before measuring guest startup. Otherwise an
    # unrelated Bazel command's lock wait can look like time spent in Codex.
    if os.environ.get('RETROOS_PREBUILT') != '1':
        subprocess.run(['bazelisk', 'build', '//:boot_disk'], cwd=ROOT, check=True,
                       stdout=subprocess.DEVNULL)
    label = ('codex-native-resume' if args.storage == 'ext4' else 'codex-smb-resume') + ('-picker' if args.picker else '') + ('-filled' if args.filled else '')
    if args.label:
        label += '-' + args.label
    if args.screen_transport == 'qmp':
        label += '-qmp'
    artifacts = ROOT / 'build/ci' / (label + ('-unprofiled' if args.no_profile else ''))
    artifacts.mkdir(parents=True, exist_ok=True)
    artifacts.chmod(0o700)
    (artifacts / 'screens.txt').write_text('')
    spec = importlib.util.spec_from_file_location('serial_bridge', ROOT / 'tools/86box_mcp.py')
    bridge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bridge)
    with tempfile.TemporaryDirectory(prefix='retroos-codex-native-') as directory:
        work = Path(directory)
        home = work / 'c'
        for name in ('RETROOS', 'TEMP', '.codex', 'work'):
            (home / name).mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / 'etc/RETROOS.INI', home / 'RETROOS/RETROOS.INI')
        state = home / '.codex'
        state.chmod(0o700)
        if args.existing_skills and (args.state_from / 'skills').is_dir():
            shutil.copytree(args.state_from / 'skills', state / 'skills', symlinks=True)
        for name in ('auth.json', 'models_cache.json'):
            source = args.state_from / name
            if source.exists():
                shutil.copyfile(source, state / name)
                (state / name).chmod(0o600)
        # Snapshot DB, WAL and SHM together, then use SQLite backup on the copy.
        # This never opens the live host database with SQLite.
        for source in args.state_from.glob('*.sqlite'):
            if source.name == 'logs_2.sqlite':
                continue
            with tempfile.TemporaryDirectory() as snapshot:
                for suffix in ('', '-wal', '-shm'):
                    candidate = Path(str(source) + suffix)
                    if candidate.exists():
                        shutil.copyfile(candidate, Path(snapshot) / candidate.name)
                with sqlite3.connect(str(Path(snapshot) / source.name)) as saved:
                    with sqlite3.connect(str(state / source.name)) as target:
                        saved.backup(target)
        if args.picker:
            with sqlite3.connect(str(state / 'state_5.sqlite')) as db:
                rows = db.execute('select id,rollout_path,cwd from threads').fetchall()
                for thread, rollout, cwd in rows:
                    source = Path(rollout)
                    if not source.is_file():
                        continue
                    try:
                        relative = source.relative_to(args.state_from)
                    except ValueError:
                        relative = Path('sessions') / source.name
                    destination = state / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(source, destination)
                    db.execute('update threads set rollout_path=?,cwd=? where id=?',
                        ('/home/retroos/.codex/' + str(relative),
                         '/home/retroos/work' if cwd == str(ROOT) else cwd, thread))
        elif args.resume:
            with sqlite3.connect(str(state / 'state_5.sqlite')) as db:
                if args.resume == 'latest':
                    latest = db.execute('select id from threads where cwd=? order by updated_at desc limit 1', (str(ROOT),)).fetchone()
                    if not latest:
                        raise RuntimeError('No saved session for this project')
                    args.resume = latest[0]
                row = db.execute('select rollout_path from threads where id=?', (args.resume,)).fetchone()
                if row and Path(row[0]).is_file():
                    destination = state / 'sessions' / Path(row[0]).name
                    destination.parent.mkdir(exist_ok=True)
                    shutil.copyfile(row[0], destination)
                    db.execute('update threads set rollout_path=?,cwd=? where id=?',
                               ('/home/retroos/.codex/sessions/' + destination.name, '/home/retroos/work', args.resume))
        if args.daemon:
            release = (args.state_from / 'packages/app-server-daemon/current').resolve(strict=True)
            packages = state / 'packages/app-server-daemon'
            shutil.copytree(release, packages / 'releases' / release.name)
            (packages / 'current').symlink_to('releases/' + release.name)
        (state / 'config.toml').write_text('model="gpt-6.1-sol"\nmodel_reasoning_effort="medium"\n'
            '[features]\n' + ('' if args.full_features else 'apps=false\nshell_snapshot=false\nplugins=false\nremote_plugin=false\n')
            + 'daemon_auto_start=' + str(args.daemon).lower() + '\n'
            + '[projects."/home/retroos/work"]\ntrust_level="trusted"\n')
        import sys
        sys.path.insert(0, str(ROOT / 'tools'))
        from setup_codex import DEFAULT_BINARY
        command = [str(DEFAULT_BINARY.resolve(strict=True))]
        if not args.daemon:
            command += ['--no-daemon']
        command += ['--no-alt-screen', '-C', '/home/retroos/work']
        if args.resume:
            command += ['resume', args.resume]
        # Gate before exec so even fast native loading cannot finish before
        # the host enables the profiler. Both storage backends get this gate.
        subprocess.run(['gcc', '-m64', '-nostdlib', '-static', '-no-pie', '-fno-pie',
            '-fno-stack-protector', '-fno-builtin', '-O2', str(ROOT / 'test/linux_program_timer.c'),
            '-o', str(home / 'timer')], check=True)
        prefix = ''
        if args.background_build:
            (home/'hello.c').write_text('#include <stdio.h>\nint main(void){puts("RESIDENT_BUILD_PASS");return 0;}\n')
            (home/'build.py').write_text('''import json, subprocess, time, sys
for name, argv in [
 ('compile', ['/usr/bin/gcc','-O2','-c','/home/retroos/hello.c','-o','/home/retroos/hello.o']),
 ('link', ['/usr/bin/gcc','/home/retroos/hello.o','-o','/home/retroos/hello']),
 ('run', ['/home/retroos/hello'])]:
 start=time.monotonic()
 p=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 print('RESIDENT_BUILD_RESULT '+json.dumps(dict(name=name,seconds=time.monotonic()-start,returncode=p.returncode)),flush=True,file=sys.stderr)
 assert p.returncode==0,p.stderr
''')
            (home/'background.py').write_text('''import subprocess,time
time.sleep(30)
p=subprocess.Popen(['/home/retroos/timer','--profile','resident-build','/usr/bin/python3','/home/retroos/build.py'],stdin=subprocess.PIPE)
time.sleep(2)
p.stdin.write(b'\\n\\n');p.stdin.flush()
assert p.wait()==0
print('RESIDENT_BUILD_COMPLETE',flush=True)
''')
            prefix = '/usr/bin/python3 /home/retroos/background.py &\n'
        (home / 'run.sh').write_text(prefix + 'exec /home/retroos/timer --profile codex ' + shlex.join(command) + '\n')
        image = native_program_profile.prepare(work, home, not args.background_build,
            extra_binaries=[str(DEFAULT_BINARY.resolve(strict=True)), '/usr/bin/ps', '/usr/bin/git', '/bin/bash', '/usr/bin/uname', '/usr/bin/realpath', '/etc/ssl/certs/ca-certificates.crt'],
            image_bytes=(16 if args.filled else 8) * 1024**3,
            allocation_fill_bytes=12 * 1024**3 if args.filled else 0)
        if args.tools_from:
            for child in ('usr/bin', 'usr/lib/x86_64-linux-gnu'):
                subprocess.run(['cp', '-al', '--remove-destination', str(args.tools_from/child)+'/.', str(work/'native-root'/child)+'/'], check=True)
            subprocess.run(['mkfs.ext4','-q','-F','-I','1024','-d',str(work/'native-root'),str(image)],check=True)
        log = artifacts / 'klog.txt'
        env = os.environ.copy()
        env.pop('RETROOS_DATA_IMAGE', None)
        env['RETROOS_PREBUILT'] = '1'
        launch = [str(ROOT / 'run.sh'), 'qemu', '--kvm', '--headless', '--sound', 'none', '--net', args.network]
        if args.storage == 'ext4':
            launch += ['--hd', 'nvme', '--data-image', str(image)]
        else:
            profile = work / 'profile.json'
            profile.write_text(json.dumps({'root': '/' if args.live_tools else str(work / 'native-root'), 'c_root': str(home)}))
            env['RETROOS_QEMU_LIVE_PROFILE'] = str(profile)
        launch += ['--cmd', '/home/retroos/RETROOS/SHELL.ELF /home/retroos/run.sh', '--', '-m', str(args.memory), '-smp', str(args.cpus)]
        comparison_socket = None
        if args.kernel:
            from boot_fixture import prepare_boot
            boot = prepare_boot(work, image, '[environment]\nTEST=/home/retroos/RETROOS/SHELL.ELF /home/retroos/run.sh\n')
            subprocess.run(['mcopy', '-o', '-i', str(boot) + '@@1048576', str(args.kernel.resolve(strict=True)), '::kernel.elf'], check=True)
            comparison_socket = work / 'mcp.sock'
            variables = work / 'vars.fd'
            shutil.copyfile(os.environ.get('OVMF_VARS', '/usr/share/OVMF/OVMF_VARS_4M.fd'), variables)
            firmware = os.environ.get('OVMF_CODE', '/usr/share/OVMF/OVMF_CODE_4M.fd')
            network = ['-nic', 'none'] if args.network == 'none' else ['-netdev', 'user,id=net0', '-device', 'virtio-net-pci,netdev=net0']
            launch = ['qemu-system-x86_64', '-accel', 'kvm', '-cpu', 'host', '-m', str(args.memory), '-smp', str(args.cpus),
                '-M', 'q35', '-nodefaults', '-device', 'bochs-display', '-device', 'qemu-xhci',
                '-drive', f'if=pflash,format=raw,readonly=on,file={firmware}',
                '-drive', f'if=pflash,format=raw,file={variables}',
                '-display', 'none', '-serial', 'none', '-serial', f'unix:{comparison_socket},server=on,wait=off',
                '-fw_cfg', 'name=opt/mcp,string=com2',
                '-no-reboot', '-debugcon', 'stdio', *network,
                '-drive', f'file={boot},format=raw,if=none,id=boot',
                '-device', 'piix3-ide,id=boot-ide', '-device', 'ide-hd,drive=boot,bus=boot-ide.0,unit=0,bootindex=1',
                '-drive', f'file={image},format=raw,if=none,id=fsdata',
                '-device', 'nvme,drive=fsdata,serial=RETROOS-CODEX']
        control = None
        qmp_screen = None
        if args.screen_transport == 'qmp':
            launch += ['-qmp', f'unix:{work / "qmp.sock"},server=on,wait=off']
        if args.direct_io:
            launch += ['-set', 'drive.' + ('fsdata' if args.kernel else 'data') + '.cache=none']
        if args.capture_network:
            launch += ['-object', f'filter-dump,id=startup_capture,netdev=net0,maxlen=54,file={artifacts / "network-headers.pcap"}']
        with log.open('w') as output:
            if comparison_socket:
                output.write(f'MCP control: {comparison_socket}\n')
                output.flush()
            process = subprocess.Popen(launch, cwd=ROOT, env=env, stdout=output, stderr=subprocess.STDOUT)
            started = time.monotonic()
            last_screen = ''
            typed_at = None
            guest_started = None
            last_profile = 0
            picker_stage = 'startup'
            picker_started = None
            selected_at = None
            picker_timings = {}
            benchmark_started = False
            benchmark_done = False
            try:
                with (artifacts / 'samples.jsonl').open('w') as samples:
                    while time.monotonic() - started < args.timeout:
                        if process.poll() is not None:
                            raise RuntimeError('Codex/guest exited; inspect private klog')
                        if control is None:
                            text = log.read_text(errors='replace')
                            match = re.search(r'MCP control: (\S+)', text)
                            if not match or 'PROFILE_READY codex' not in text:
                                time.sleep(.2)
                                continue
                            control = bridge.SerialControl(None, match.group(1))
                            if args.screen_transport == 'qmp':
                                from qmp_screen import Screen
                                qmp_screen = Screen(work / 'qmp.sock', control, work / 'terminal.bin')
                            if not args.no_profile:
                                control.request('profile reset')
                                control.request('profile on')
                            guest_started = time.monotonic()
                            control.request('key enter')
                        elapsed = time.monotonic() - started
                        if args.background_build:
                            text = log.read_text(errors='replace')
                            if not benchmark_started and 'PROFILE_READY resident-build' in text:
                                if typed_at is None:
                                    raise RuntimeError('Background build began before Codex became ready')
                                control.request('profile reset')
                                control.request('profile on')
                                benchmark_started = True
                            match = re.search(r'PROFILE_DONE resident-build (\d+)ns', text)
                            if benchmark_started and match and not benchmark_done:
                                result = {'workload_ns':int(match.group(1)), 'codex_resumed':args.resume,
                                    'commands':[json.loads(row) for row in re.findall(r'RESIDENT_BUILD_RESULT (\{[^\n]*\})',text)]}
                                for name in ('profile totals','profile execution','profile io','profile top'):
                                    result[name]=control.request(name,timeout=20)
                                (artifacts/'resident-build.json').write_text(json.dumps(result,indent=2)+'\n')
                                print('Resident Codex build: '+str(result['workload_ns']/1e9)+' s',flush=True)
                                benchmark_done = True
                        screen = qmp_screen.read() if qmp_screen else bytes.fromhex(control.request('screen', timeout=20)['texthex']).decode()
                        if screen != last_screen:
                            (artifacts / 'screen.txt').write_text(screen)
                            with (artifacts / 'screens.txt').open('a') as history:
                                history.write(f'\n--- {elapsed:.3f}s ---\n' + screen)
                            last_screen = screen
                        if re.search(r'\[mem\] exit tid=1 code=[1-9]', log.read_text(errors='replace')):
                            raise RuntimeError('Codex startup failed; inspect private screen')
                        ready = 'context left' in screen or re.search(r'gpt-6\.1-sol\s+(?:medium|default)\s+·', screen, re.I)
                        if args.picker and picker_stage == 'startup' and ready:
                            picker_timings['startup_s'] = time.monotonic() - guest_started
                            if not args.no_profile:
                                control.request('profile reset')
                            control.request('texthex ' + b'/resume'.hex())
                            picker_stage = 'command'
                            time.sleep(.1)
                            continue
                        if args.picker and picker_stage == 'command':
                            # Text injection is queued; wait until the complete
                            # command is visible before sending Enter. Otherwise
                            # the /re prefix can select /review on a slow guest.
                            if re.search(r'(?m)^\s*[›>■]\s*/resume\s*$', screen):
                                picker_started = time.monotonic()
                                control.request('key enter')
                                picker_stage = 'listing'
                            time.sleep(.1)
                            continue
                        if args.picker and picker_stage == 'listing':
                            if re.search(r'Resume (?:a )?(?:previous |past )?session', screen, re.I) and 'Loading' not in screen and ('ago' in screen or re.search(r'\d{4}-\d\d-\d\d', screen)):
                                picker_timings['listing_s'] = time.monotonic() - picker_started
                                if not args.no_profile:
                                    picker_timings['listing_profile'] = {name: control.request(name, timeout=20)
                                        for name in ('profile totals', 'profile execution', 'profile io', 'profile top')}
                                    control.request('profile reset')
                                selected_at = time.monotonic()
                                control.request('key enter')
                                picker_stage = 'loading'
                                print(f'Picker listed sessions in {picker_timings["listing_s"]:.3f}s', flush=True)
                            time.sleep(.1)
                            continue
                        if args.picker and picker_stage == 'loading' and re.search(r'Resume (?:a )?(?:previous |past )?session', screen, re.I):
                            time.sleep(.1)
                            continue
                        # Match the startup choice itself, not words quoted
                        # in resumed tool output. Never press Enter on a draft.
                        update_choice = re.search(r'(?m)^\s*[›>■]?\s*1[.)]?\s+Update now', screen)
                        if typed_at is None and not ready and update_choice and 'Skip' in screen:
                            control.request('key down')
                            control.request('key enter')
                        if ready and typed_at is None:
                            detected_at = time.monotonic()
                            ready_sample = {'elapsed': elapsed, 'storage': args.storage,
                                'since_gate_s': detected_at - guest_started, 'profiling': not args.no_profile,
                                'screen_transport': args.screen_transport}
                            if not args.no_profile:
                                for name in ('profile totals', 'profile top', 'profile execution', 'profile io'):
                                    ready_sample[name] = control.request(name, timeout=20)
                            if args.picker:
                                picker_timings['loading_s'] = detected_at - selected_at
                                ready_sample['picker'] = picker_timings
                            (artifacts / 'ready-sample.json').write_text(json.dumps(ready_sample, indent=2) + '\n')
                            print(f'Codex ready at {elapsed:.3f}s after VM launch, '
                                  f'{time.monotonic() - guest_started:.3f}s after guest control became available; '
                                  'typing a draft without submitting', flush=True)
                            control.request('texthex ' + b'RESUME_TYPING_PROBE'.hex())
                            typed_at = time.monotonic()
                        if typed_at and 'RESUME_TYPING_PROBE' in screen and time.monotonic() - typed_at >= 5 and (not args.background_build or benchmark_done):
                            if not args.no_profile:
                                control.request('profile dump', timeout=20)
                            print(f'PASS: Codex accepts typing after {"resume" if args.resume else "startup"} at {elapsed:.3f}s', flush=True)
                            break
                        if not args.no_profile and args.sample_interval > 0 and elapsed - last_profile >= args.sample_interval:
                            sample = {'elapsed': elapsed}
                            for name in ('profile totals', 'profile top', 'profile execution', 'profile io'):
                                sample[name] = control.request(name, timeout=20)
                            samples.write(json.dumps(sample) + '\n')
                            samples.flush()
                            last_profile = elapsed
                        time.sleep(.025 if qmp_screen else .5)
                    else:
                        if control:
                            control.request('debug dump', timeout=20)
                        raise RuntimeError('Native Codex startup/resume/typing timed out; inspect private artifacts')
            finally:
                if qmp_screen:
                    qmp_screen.close()
                if control:
                    control.close()
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=15)
                if args.daemon and args.storage == 'ext4':
                    # Keep background startup failures that never reach the
                    # terminal, before the private fixture is discarded.
                    with (artifacts / 'daemon-stderr.txt').open('w') as saved:
                        subprocess.run(['debugfs', '-R',
                            'cat /home/retroos/.codex/app-server-daemon/daemon.stderr.log', str(image)],
                            stdout=saved, stderr=subprocess.DEVNULL, check=False)
                elif args.daemon:
                    stderr = home / '.codex/app-server-daemon/daemon.stderr.log'
                    if stderr.exists():
                        shutil.copyfile(stderr, artifacts / 'daemon-stderr.txt')


if __name__ == '__main__':
    main()
