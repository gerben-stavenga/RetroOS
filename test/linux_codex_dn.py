#!/usr/bin/env python3
"""Exercise installed Codex state through DN, its DOS helper, and shell in KVM.

Uses the supplied guest home as writable state, without replacing its config,
packages or caches. --tools submits a bounded command and confirms only that
command's approval prompt. Requires the installed guest login and Codex wrapper.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import time
import uuid
from qmp_screen import Screen

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--home', type=Path, required=True)
    parser.add_argument('--project', default=str(ROOT))
    parser.add_argument('--tools', action='store_true')
    parser.add_argument('--profile', action='store_true')
    parser.add_argument('--timeout', type=float, default=240)
    parser.add_argument('--label', default='startup')
    options = parser.parse_args()
    home = options.home.resolve(strict=True)
    assert (home / 'bin/codex').is_file(), 'Guest Codex wrapper is missing'
    assert re.fullmatch(r'[a-zA-Z0-9_-]+', options.label), 'Invalid artifact label'
    artifacts = ROOT / 'build/ci' / ('codex-dn-' + options.label)
    artifacts.mkdir(parents=True, exist_ok=True)
    artifacts.chmod(0o700)
    spec = importlib.util.spec_from_file_location('bridge', ROOT / 'tools/86box_mcp.py')
    bridge = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bridge)
    token = uuid.uuid4().hex[:6]
    batch = home / ('CX' + token + '.BAT')
    marker_name = 'dn-tool-' + token + '.txt'
    marker = home / '.codex/diagnostics' / marker_name
    marker.parent.mkdir(parents=True, exist_ok=True)
    guest_marker = '/home/retroos/.codex/diagnostics/' + marker_name
    command = "printf '%s\\n' DN_TOOL_PASS > " + guest_marker + ' && cat ' + guest_marker
    prompt = ('Use your command tool to execute exactly `' + command
              + '`. Reply DN_TOOL_PASS only after the command succeeds.')
    result = {'state': 'starting'}
    with tempfile.TemporaryDirectory(prefix='retroos-codex-dn-') as directory:
        work = Path(directory)
        (work / 'profile.json').write_text(json.dumps({'root': '/', 'c_root': str(home)}))
        env = dict(os.environ, RETROOS_PREBUILT='1', AUDIO_BACKEND='none',
                   RETROOS_QEMU_LIVE_PROFILE=str(work / 'profile.json'))
        env.pop('RETROOS_DATA_IMAGE', None)
        batch.write_bytes(b'C:\\RETROOS\\SHELL.ELF\r\n')
        log = artifacts / 'klog.txt'
        control = screen = None
        with log.open('w') as output:
            process = subprocess.Popen([str(ROOT / 'run.sh'), 'qemu', '--kvm', '--headless',
                '--sound', 'hda', '--', '-m', '2048', '-smp', '2',
                '-qmp', f'unix:{work}/qmp.sock,server=on,wait=off'],
                cwd=ROOT, env=env, stdout=output, stderr=subprocess.STDOUT)
            start = time.monotonic()
            shell_at = command_at = ready_at = sent_at = marker_at = None
            next_sample = 0
            try:
                while time.monotonic() - start < options.timeout:
                    elapsed = time.monotonic() - start
                    text = log.read_text(errors='replace')
                    assert process.poll() is None, 'QEMU exited; see klog'
                    if control is None:
                        match = re.search(r'MCP control: (\S+)', text)
                        if not match or 'event_loop entered' not in text:
                            time.sleep(.1)
                            continue
                        control = bridge.SerialControl(None, match[1])
                        screen = Screen(work / 'qmp.sock', control, artifacts / 'terminal.bin')

                    def type_text(value):
                        data = value.encode()
                        for offset in range(0, len(data), 30):
                            control.request('texthex ' + data[offset:offset + 30].hex())
                            time.sleep(.1)
                        time.sleep(.2)
                        control.request('key enter')

                    if shell_at is None and elapsed > 12:
                        type_text('C:\\RETROOS\\COMMAND.COM /B C:\\' + batch.name)
                        shell_at = elapsed
                    if shell_at is not None and command_at is None and elapsed > shell_at + 5:
                        if options.profile:
                            control.request('profile reset')
                            control.request('profile on')
                        type_text('/home/retroos/bin/codex --no-alt-screen -C ' + shlex.quote(options.project))
                        command_at = time.monotonic() - start
                    view = screen.read()
                    (artifacts / 'screen.txt').write_text(view)
                    if re.search(r'(?m)^\s*[>›■]?\s*1[.)]?\s+Update now', view) and 'Skip' in view:
                        control.request('key down')
                        control.request('key enter')
                    if ('app server did not become ready' in text or 'failed to record pid-managed' in text
                            or 'account/read failed during TUI bootstrap' in text):
                        result = {'state': 'failed', 'seconds': elapsed}
                        break
                    ready = 'context left' in view or re.search(r'gpt-6\.1-sol\s+(?:medium|default)\s+·', view, re.I)
                    if ready and ready_at is None:
                        ready_at = elapsed
                        result = {'state': 'ready', 'seconds': elapsed, 'startup_seconds': elapsed - command_at}
                        print(json.dumps(result), flush=True)
                        if not options.tools:
                            break
                    if ready_at is not None and sent_at is None and elapsed > ready_at + 3:
                        type_text(prompt)
                        sent_at = elapsed
                    if sent_at is not None and 'Press enter to confirm' in view and marker_name in view:
                        control.request('key enter')
                    if sent_at is not None and marker.exists() and marker.read_text().strip() == 'DN_TOOL_PASS':
                        if marker_at is None:
                            marker_at = elapsed
                        if elapsed > marker_at + 3:
                            result = dict(result, state='tool-passed', tool_seconds=elapsed - sent_at)
                            break
                    if options.profile and command_at is not None and elapsed >= next_sample:
                        sample = {'seconds': elapsed}
                        for name in ('profile totals', 'profile io', 'profile top'):
                            sample[name] = control.request(name, timeout=20)
                        with (artifacts / 'samples.jsonl').open('a') as samples:
                            samples.write(json.dumps(sample) + '\n')
                        next_sample = elapsed + 10
                    time.sleep(.1)
                else:
                    result = dict(result, state='timeout')
            finally:
                (artifacts / 'report.json').write_text(json.dumps(result, indent=2) + '\n')
                if screen:
                    screen.close()
                if control:
                    control.close()
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=20)
                batch.unlink()
    print(json.dumps(result), flush=True)
    assert result['state'] == ('tool-passed' if options.tools else 'ready'), result


if __name__ == '__main__':
    main()
