#!/usr/bin/env python3
"""Ask the interactive Codex TUI for a response in QEMU/KVM with live SMB files.

Uses a private copy of the saved login and a separate home. No model tools are
requested. Terminal text and a screenshot are retained, credentials are not.
"""
import json
import os
import re
from pathlib import Path
import shlex
import shutil
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from setup_codex import setup, DEFAULT_BINARY

EXPECTED = 'Hello from interactive Codex on RetroOS.'


def main():
    artifacts = ROOT / 'build/ci/codex-interactive'
    artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='retroos-interactive-') as directory:
        work = Path(directory)
        home = work / 'c'
        for child in ('RETROOS', 'TEMP', 'work'):
            (home / child).mkdir(parents=True)
        shutil.copyfile(ROOT / 'etc/RETROOS.INI', home / 'RETROOS/RETROOS.INI')
        setup(home, DEFAULT_BINARY, Path(os.environ.get('CODEX_HOME', Path.home() / '.codex')))
        (home / '.codex/config.toml').write_text(
            'model = "gpt-6.1-sol"\nmodel_reasoning_effort = "medium"\n'
            '[projects."/home/retroos/work"]\ntrust_level = "trusted"\n')
        # The SMB backend follows host symlinks but cannot expose their target
        # bytes. Invoke the package entrypoint explicitly for resource lookup.
        command = [str(DEFAULT_BINARY), '--no-daemon', '--no-alt-screen',
                   '--disable', 'apps', '--disable', 'shell_snapshot',
                   '--sandbox', 'read-only', '-C', '/home/retroos/work']
        (home / 'run.sh').write_text('exec ' + shlex.join(command) + '\n')
        profile = work / 'profile.json'
        profile.write_text(json.dumps({'root': '/', 'c_root': str(home)}))
        env = os.environ.copy()
        env.pop('RETROOS_DATA_IMAGE', None)
        env['RETROOS_QEMU_LIVE_PROFILE'] = str(profile)
        control_path, qmp_path = work / 'control', work / 'qmp'
        with (artifacts / 'klog.txt').open('w') as log:
            process = subprocess.Popen([str(ROOT / 'run.sh'), 'qemu', '--kvm',
                '--headless', '--sound', 'none', '--cmd',
                '/home/retroos/RETROOS/SHELL.ELF /home/retroos/run.sh', '--',
                '-m', '2048',
                '-qmp', f'unix:{qmp_path},server=on,wait=off'],
                cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT)
            control = socket.socket(socket.AF_UNIX)
            stream = None
            screens = []
            try:
                deadline = time.monotonic() + 240
                while time.monotonic() < deadline:
                    text = (artifacts / 'klog.txt').read_text(errors='replace')
                    if match := re.search(r'MCP control: (\S+)', text):
                        control_path = Path(match.group(1))
                    if 'event_loop entered' in text and control_path.exists():
                        control.connect(str(control_path))
                        control.settimeout(30)
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
                sent = False
                submitted_at = 0
                late_trace = False
                while time.monotonic() < deadline:
                    result = request('screen')
                    screen = bytes.fromhex(result['texthex']).decode()
                    if not screens or screen != screens[-1]:
                        screens.append(screen)
                        (artifacts / 'screens.txt').write_text('\n\n--- screen ---\n\n'.join(screens))
                        (artifacts / 'screen.txt').write_text(screen)
                    if sent and not late_trace and os.environ.get('RETROOS_INTERACTIVE_TRACE_DELAY') and time.monotonic() - submitted_at > float(os.environ['RETROOS_INTERACTIVE_TRACE_DELAY']):
                        request('trace on')
                        late_trace = True
                    # Only enter a prompt after the interactive editor appears.
                    if not sent and ('Ask Codex to do anything' in screen or 'context left' in screen or 'gpt-6.1-sol' in screen and 'directory:' in screen):
                        prompt = 'Reply exactly: ' + EXPECTED + ' Do not use any tools or read any files.'
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
                    if sent and EXPECTED in screen and ('• ' + EXPECTED in screen or '● ' + EXPECTED in screen):
                        print('PASS: interactive Codex replied: ' + EXPECTED, flush=True)
                        break
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
                errors = []
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
                                    "SELECT level,target,feedback_log_body FROM logs WHERE level IN ('WARN','ERROR') ORDER BY id"):
                                    line = f'{level} {target}: {message}'
                                    errors.append(re.sub(r'Bearer\s+\S+|eyJ[A-Za-z0-9_.-]+|sk-[A-Za-z0-9_-]+', '[redacted]', line))
                        except sqlite3.Error:
                            errors.append('Could not recover the runtime-log snapshot.')
                (artifacts / 'application-errors.txt').write_text('\n'.join(errors))
                if stream is not None:
                    stream.close()
                control.close()
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=15)


if __name__ == '__main__':
    main()
