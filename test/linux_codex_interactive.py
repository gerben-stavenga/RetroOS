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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from setup_codex import setup, DEFAULT_BINARY

EXPECTED = 'Hello from interactive Codex on RetroOS.'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--daemon', action='store_true', help='Exercise the background server')
    parser.add_argument('--tools', action='store_true', help='Execute a command through the code-mode host in the private VM')
    parser.add_argument('--tools-readonly', action='store_true', help='Read an unknown marker through the command tool with the read-only sandbox')
    options = parser.parse_args()
    if options.tools_readonly:
        options.tools = True
    label = 'codex-tools-readonly' if options.tools_readonly else 'codex-tools' if options.tools else 'codex-interactive'
    artifacts = ROOT / 'build/ci' / (label + ('-daemon' if options.daemon else ''))
    expected = 'CODEX_READ_PASS_' + secrets.token_hex(8) if options.tools_readonly else 'CODEX_TOOL_PASS' if options.tools else EXPECTED
    artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='retroos-interactive-') as directory:
        work = Path(directory)
        home = work / 'c'
        for child in ('RETROOS', 'TEMP', 'work'):
            (home / child).mkdir(parents=True)
        shutil.copyfile(ROOT / 'etc/RETROOS.INI', home / 'RETROOS/RETROOS.INI')
        if options.tools_readonly:
            (home / 'work/tool-input.txt').write_text(expected + '\n')
        setup(home, DEFAULT_BINARY, Path(os.environ.get('CODEX_HOME', Path.home() / '.codex')))
        (home / '.codex/config.toml').write_text(
            'model = "gpt-6.1-sol"\nmodel_reasoning_effort = "medium"\n'
            '[projects."/home/retroos/work"]\ntrust_level = "trusted"\n')
        # Exercise the ordinary PATH launcher, including installed-package
        # discovery through SMB rather than bypassing it with the binary path.
        command = ['codex', '--no-alt-screen',
                   '--disable', 'apps', '--disable', 'shell_snapshot',
                   '--disable', 'plugins', '--disable', 'remote_plugin',
                   '-C', '/home/retroos/work']
        command += ['--dangerously-bypass-approvals-and-sandbox'] if options.tools and not options.tools_readonly else ['--sandbox', 'read-only']
        if not options.daemon:
            command.insert(1, '--no-daemon')
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
                debugged = False
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
                    if sent and not debugged and time.monotonic() - submitted_at > 20:
                        request('debug dump')
                        debugged = True
                    # The editor appears while the session is still loading;
                    # Enter then leaves text in the draft instead of starting
                    # a turn. Wait for the model/status footer before typing.
                    ready = 'context left' in screen or re.search(r'gpt-6\.1-sol\s+(?:medium|default)\s+·', screen, re.IGNORECASE)
                    if not sent and ready:
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
                        if options.tools and not options.tools_readonly:
                            assert (home / 'work/tool-result.txt').read_text() == 'CODEX_TOOL_PASS\n'
                        print('PASS: interactive Codex replied: ' + expected, flush=True)
                        break
                    if options.tools and 'failed to spawn code-mode host' in screen:
                        request('debug dump')
                        raise RuntimeError('Code-mode host failed to spawn; see ' + str(artifacts))
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
