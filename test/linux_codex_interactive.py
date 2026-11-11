#!/usr/bin/env python3
"""Ask the interactive Codex TUI for a response in QEMU/KVM with live SMB files.

Uses a private copy of the saved login and a separate home. Tool execution is
optional. Terminal text and a screenshot are retained, credentials are not.
"""
import argparse
import json
import os
import re
import secrets
from pathlib import Path
import shlex
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import tomllib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from setup_codex import setup, DEFAULT_BINARY

EXPECTED = 'Hello from interactive Codex on RetroOS.'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--storage', choices=('ide', 'nvme'), default='ide', help='Controller for the private ext4 home disk')
    parser.add_argument('--memory', type=int, default=2048, help='Guest RAM in MiB')
    parser.add_argument('--managed-daemon', type=Path, help='Use an existing managed daemon release through a private package selection')
    parser.add_argument('--binary', type=Path, default=DEFAULT_BINARY, help='Native Codex binary to expose inside the private guest home')
    parser.add_argument('--raw-state', action='store_true', help='Preserve copied SQLite WAL and shared-memory files when seeding state')
    parser.add_argument('--state-from', type=Path, help='Seed private SQLite databases from snapshots of an existing Codex home')
    parser.add_argument('--ext4-home', action='store_true', help='Keep writable guest home on native ext4; export host tools read-only over SMB')
    parser.add_argument('--daemon', action='store_true', help='Exercise the background server')
    parser.add_argument('--stale-daemon-link', action='store_true', help='Seed a dangling daemon socket alias from the home owner before boot')
    parser.add_argument('--untrusted', action='store_true', help='Accept the project trust prompt and verify config persistence')
    parser.add_argument('--tools', action='store_true', help='Execute a command through the code-mode host in the private VM')
    parser.add_argument('--tools-readonly', action='store_true', help='Read an unknown marker through the command tool with the read-only sandbox')
    parser.add_argument('--timeout', type=float, default=240, help='Total guest startup and request deadline in seconds')
    parser.add_argument('--control-timeout', type=float, default=30, help='Diagnostic control request timeout in seconds')
    options = parser.parse_args()
    if options.raw_state and not options.state_from:
        parser.error('--raw-state requires --state-from')
    if options.stale_daemon_link and not (options.daemon and options.ext4_home):
        parser.error('--stale-daemon-link requires --daemon --ext4-home')
    if options.untrusted and options.tools:
        parser.error('--untrusted exercises default onboarding; run command-tool checks separately')
    if options.tools_readonly:
        options.tools = True
    label = 'codex-tools-readonly' if options.tools_readonly else 'codex-tools' if options.tools else 'codex-interactive'
    artifacts = ROOT / 'build/ci' / (label + ('-daemon' if options.daemon else '') + ('-trust' if options.untrusted else '') + ('-ext4' if options.ext4_home else '') + ('-state' if options.state_from else '') + ('-raw' if options.raw_state else '') + (f'-ram{options.memory}' if options.memory != 2048 else '') + ('-nvme' if options.storage == 'nvme' else ''))
    if options.stale_daemon_link:
        artifacts = artifacts.with_name(artifacts.name + '-stale-link')
    expected = 'CODEX_READ_PASS_' + secrets.token_hex(8) if options.tools_readonly else 'CODEX_TOOL_PASS' if options.tools else EXPECTED
    artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='retroos-interactive-') as directory:
        work = Path(directory)
        home = work / 'image-root/home/retroos' if options.ext4_home else work / 'c'
        for child in ('RETROOS', 'TEMP', 'work'):
            (home / child).mkdir(parents=True)
        if options.untrusted:
            subprocess.run(['git', 'init', '--quiet', str(home / 'work')], check=True)
        shutil.copyfile(ROOT / 'etc/RETROOS.INI', home / 'RETROOS/RETROOS.INI')
        if options.tools_readonly:
            (home / 'work/tool-input.txt').write_text(expected + '\n')
        setup(home, options.binary, Path(os.environ.get('CODEX_HOME', Path.home() / '.codex')))
        if options.stale_daemon_link:
            import hashlib
            alias = '/home/retroos/.codex/app-server-control/app-server-control.sock'
            target = f'/tmp/codex-daemon-{home.stat().st_uid}/' + hashlib.sha256(alias.encode()).hexdigest()
            control_dir = home / '.codex/app-server-control'
            control_dir.mkdir(mode=0o700, exist_ok=True)
            (control_dir / 'app-server-control.sock').symlink_to(target)
        if options.managed_daemon:
            release = options.managed_daemon.resolve(strict=True)
            packages = home / '.codex/packages/app-server-daemon'
            (packages / 'releases').mkdir(parents=True)
            (packages / 'releases' / release.name).symlink_to(release, target_is_directory=True)
            (packages / 'current').symlink_to('releases/' + release.name, target_is_directory=True)
        first_runtime_log_id = 0
        if options.state_from:
            with tempfile.TemporaryDirectory(prefix='retroos-state-snapshot-') as snapshot:
                for source in sorted(options.state_from.glob('*.sqlite')):
                    for name in (source.name, source.name + '-wal', source.name + '-shm'):
                        candidate = options.state_from / name
                        if candidate.exists():
                            shutil.copyfile(candidate, Path(snapshot) / name)
                            if options.raw_state:
                                shutil.copyfile(Path(snapshot) / name, home / '.codex' / name)
                    with sqlite3.connect(str(Path(snapshot) / source.name)) as database:
                        if not options.raw_state:
                            with sqlite3.connect(str(home / '.codex' / source.name)) as destination:
                                database.backup(destination)
                        if source.name == 'logs_2.sqlite':
                            first_runtime_log_id = database.execute('SELECT coalesce(max(id),0) FROM logs').fetchone()[0]
            print('Seeded private SQLite state from snapshots.', flush=True)
        (home / '.codex/config.toml').write_text(
            'model = "gpt-6.1-sol"\nmodel_reasoning_effort = "medium"\n'
            '[features]\napps = false\nshell_snapshot = false\nplugins = false\nremote_plugin = false\n'
            + ('daemon_auto_start = true\n' if options.daemon else 'daemon_auto_start = false\n')
            + ('' if options.untrusted else '[projects."/home/retroos/work"]\ntrust_level = "trusted"\n'))
        # Exercise the ordinary PATH launcher, including installed-package
        # discovery through SMB rather than bypassing it with the binary path.
        command = ['codex', '--no-alt-screen', '-C', '/home/retroos/work']
        if not options.untrusted:
            command += ['--dangerously-bypass-approvals-and-sandbox'] if options.tools and not options.tools_readonly else ['--sandbox', 'read-only']
        if not options.daemon:
            command.insert(1, '--no-daemon')
        (home / 'run.sh').write_text('exec ' + shlex.join(command) + '\n')
        profile = work / 'profile.json'
        profile_data = {'root': '/', 'c_root': str(home)}
        extra_drives = []
        if options.ext4_home:
            data = work / 'home.img'
            with data.open('wb') as output:
                output.truncate(2 * 1024 * 1024 * 1024 if options.state_from else 256 * 1024 * 1024)
            subprocess.run(['mkfs.ext4', '-q', '-F', '-d', str(work / 'image-root'), str(data)], check=True)
            profile_data['native_home_image'] = str(data)
            extra_drives = (['-drive', f'file={data},format=raw,if=none,id=nativehome',
                             '-device', 'nvme,drive=nativehome,serial=RETROOS-CODEX-TEST']
                            if options.storage == 'nvme' else ['-drive', f'file={data},format=raw,if=ide,index=1'])
        profile.write_text(json.dumps(profile_data))
        env = os.environ.copy()
        env.pop('RETROOS_DATA_IMAGE', None)
        env['RETROOS_QEMU_LIVE_PROFILE'] = str(profile)
        control_path, qmp_path = work / 'control', work / 'qmp'
        with (artifacts / 'klog.txt').open('w') as log:
            process = subprocess.Popen([str(ROOT / 'run.sh'), 'qemu', '--kvm',
                '--headless', '--sound', 'none', '--cmd',
                '/home/retroos/RETROOS/SHELL.ELF /home/retroos/run.sh', '--',
                '-m', str(options.memory),
                '-qmp', f'unix:{qmp_path},server=on,wait=off', *extra_drives],
                cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
            control = socket.socket(socket.AF_UNIX)
            stream = None
            screens = []
            try:
                deadline = time.monotonic() + options.timeout
                while time.monotonic() < deadline:
                    text = (artifacts / 'klog.txt').read_text(errors='replace')
                    if match := re.search(r'MCP control: (\S+)', text):
                        control_path = Path(match.group(1))
                    if 'event_loop entered' in text and control_path.exists():
                        control.connect(str(control_path))
                        control.settimeout(options.control_timeout)
                        stream = control.makefile('rb')
                        break
                    if process.poll() is not None:
                        raise RuntimeError('Guest exited during startup; see ' + str(artifacts))
                    time.sleep(.2)
                assert stream is not None, 'No diagnostic control connection'

                def request(command):
                    control.sendall(command.encode() + b'\n')
                    return json.loads(stream.readline())

                if os.environ.get('RETROOS_INTERACTIVE_TRACE'):
                    request('trace on')
                startup_debugged = False
                trust_accepted = False
                sent = False
                submitted_at = 0
                resubmitted = False
                late_trace = False
                debugged = False
                while time.monotonic() < deadline:
                    if not startup_debugged and time.monotonic() > deadline - options.timeout + 75:
                        request('debug dump')
                        startup_debugged = True
                    result = request('screen')
                    screen = bytes.fromhex(result['texthex']).decode()
                    if not screens or screen != screens[-1]:
                        screens.append(screen)
                        (artifacts / 'screens.txt').write_text('\n\n--- screen ---\n\n'.join(screens))
                        (artifacts / 'screen.txt').write_text(screen)
                    if options.untrusted and not trust_accepted and 'Trust and continue' in screen:
                        request('key enter')
                        trust_accepted = True
                        print('Accepted the private project trust prompt.', flush=True)
                    if 'failed to persist' in screen.lower():
                        raise RuntimeError('Trust persistence failed; see ' + str(artifacts))
                    if options.daemon and 'failed to record pid-managed' in (artifacts / 'klog.txt').read_text(errors='replace'):
                        raise RuntimeError('Background server PID recording failed; see ' + str(artifacts))
                    if sent and not late_trace and os.environ.get('RETROOS_INTERACTIVE_TRACE_DELAY') and time.monotonic() - submitted_at > float(os.environ['RETROOS_INTERACTIVE_TRACE_DELAY']):
                        request('trace on')
                        late_trace = True
                    # The model footer can appear before thread creation has
                    # finished. Retry Enter once only when our text remains in
                    # the nonempty editor and no turn is running.
                    if (sent and not resubmitted and time.monotonic() - submitted_at > 20
                            and 'esc to interrupt' not in screen
                            and 'Ask Codex to do anything' not in screen
                            and prompt[:16] in screen):
                        request('key enter')
                        resubmitted = True
                        submitted_at = time.monotonic()
                        print('Submitted the startup draft after thread initialization.', flush=True)
                    if sent and not debugged and time.monotonic() - submitted_at > 20:
                        request('debug dump')
                        debugged = True
                    # The editor appears while the session is still loading;
                    # Enter then leaves text in the draft instead of starting
                    # a turn. Wait for the model/status footer before typing.
                    ready = 'context left' in screen or re.search(r'gpt-6\.1-sol\s+(?:medium|default)\s+·', screen, re.IGNORECASE)
                    if not sent and ready:
                        assert not options.untrusted or trust_accepted, 'Project trust prompt was skipped'
                        prompt = ('Use your command tool to execute exactly this shell command: `'
                            "printf '%s\\n' CODEX_TOOL_PASS > /home/retroos/work/tool-result.txt && cat /home/retroos/work/tool-result.txt`. "
                            'Reply exactly CODEX_TOOL_PASS only after the command succeeds.'
                            if options.tools else 'Reply exactly: ' + expected + ' Do not use any tools or read any files.')
                        if options.tools_readonly:
                            prompt = ('Use your command tool to run cat /home/retroos/work/tool-input.txt. '
                                'Reply only with the file contents as plain text, without a code fence.')
                        for offset in range(0, len(prompt), 30):
                            request('texthex ' + prompt[offset:offset + 30].encode().hex())
                            time.sleep(.12)
                        time.sleep(.4)
                        request('key enter')
                        sent = True
                        submitted_at = time.monotonic()
                        print('Submitted prompt through the guest keyboard.', flush=True)
                    # The expected phrase must appear in the assistant turn,
                    # not just the input/prompt echoed by the terminal.
                    if sent and expected in screen and ('• ' + expected in screen or '● ' + expected in screen):
                        request('debug dump')
                        print('PASS: interactive Codex replied: ' + expected, flush=True)
                        break
                    failures = ('failed to spawn code-mode host', 'failed to create unified exec process',
                                'command tool failed to create a process', 'command tool failed to start')
                    if options.tools and any(failure in screen.lower() for failure in failures):
                        request('debug dump')
                        raise RuntimeError('Command tool failed; see ' + str(artifacts))
                    if process.poll() is not None:
                        raise RuntimeError('Interactive Codex exited; see ' + str(artifacts))
                    time.sleep(2)
                else:
                    raise RuntimeError('Interactive response timed out; see ' + str(artifacts))
            finally:
                if qmp_path.exists() and process.poll() is None:
                    try:
                        with socket.socket(socket.AF_UNIX) as qmp:
                            qmp.settimeout(5)
                            qmp.connect(str(qmp_path))
                            messages = qmp.makefile('rb')
                            messages.readline()
                            for command in [dict(execute='qmp_capabilities'),
                                dict(execute='screendump', arguments={'filename': str(artifacts / 'screen.ppm')})]:
                                qmp.sendall(json.dumps(command).encode() + b'\n')
                                while 'return' not in json.loads(messages.readline()):
                                    pass
                    except (OSError, ValueError):
                        pass
                if stream is not None:
                    stream.close()
                control.close()
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=15)
                if options.ext4_home:
                    # Inspect a stopped private disk, never a mounted live filesystem.
                    home = work / 'recovered'
                    for name in ('.codex/config.toml', '.codex/logs_2.sqlite', '.codex/logs_2.sqlite-wal',
                                 '.codex/app-server-daemon/daemon.stderr.log', '.codex/app-server-daemon/daemon.pid', 'work/tool-result.txt'):
                        destination = home / name
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        subprocess.run(['debugfs', '-R', f'dump /home/retroos/{name} {destination}', str(data)],
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                errors = []
                daemon_errors = home / '.codex/app-server-daemon/daemon.stderr.log'
                if daemon_errors.exists():
                    errors.extend(daemon_errors.read_text(errors='replace').splitlines())
                for application_log in (home / '.codex/log').glob('*.log'):
                    for line in application_log.read_text(errors='replace').splitlines():
                        if 'WARN' in line or 'ERROR' in line:
                            line = re.sub(r'Bearer\s+\S+|eyJ[A-Za-z0-9_.-]+|sk-[A-Za-z0-9_-]+', '[redacted]', line)
                            errors.append(line)
                # The CLI stores its runtime log in SQLite. Recover a private
                # snapshot, never open the live guest database from Linux.
                with tempfile.TemporaryDirectory(prefix='retroos-codex-log-') as snapshot:
                    for name in ('logs_2.sqlite', 'logs_2.sqlite-wal'):
                        source = home / '.codex' / name
                        if source.exists():
                            shutil.copyfile(source, Path(snapshot) / name)
                    if (Path(snapshot) / 'logs_2.sqlite').exists():
                        try:
                            with sqlite3.connect(str(Path(snapshot) / 'logs_2.sqlite')) as database:
                                for level, target, message in database.execute(
                                    "SELECT level,target,feedback_log_body FROM logs WHERE level IN ('WARN','ERROR') AND id > ? ORDER BY id", (first_runtime_log_id,)):
                                    line = f'{level} {target}: {message}'
                                    errors.append(re.sub(r'Bearer\s+\S+|eyJ[A-Za-z0-9_.-]+|sk-[A-Za-z0-9_-]+', '[redacted]', line))
                        except sqlite3.Error:
                            errors.append('Could not recover the runtime-log snapshot.')
                (artifacts / 'application-errors.txt').write_text('\n'.join(errors))

            if options.daemon:
                pid_file = home / '.codex/app-server-daemon/daemon.pid'
                assert pid_file.exists() and pid_file.stat().st_size > 0, 'No daemon PID record: daemon mode was not exercised'
                print('PASS: background server created its PID record.', flush=True)
            if options.tools and not options.tools_readonly:
                assert (home / 'work/tool-result.txt').read_text() == 'CODEX_TOOL_PASS\n'
            if options.untrusted:
                config = tomllib.loads((home / '.codex/config.toml').read_text())
                assert trust_accepted and config['projects']['/home/retroos/work']['trust_level'] == 'trusted', config
                print('PASS: project trust saved into the existing config.toml.', flush=True)

if __name__ == '__main__':
    main()
