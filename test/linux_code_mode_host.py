#!/usr/bin/env python3
"""Probe the installed code-mode helper without a model or login."""
import argparse
import json
from pathlib import Path
import shlex
import shutil
import struct
import tempfile
import sys
from linux_smb_symlink import ROOT, launch

sys.path.insert(0, str(ROOT / 'tools'))
from setup_codex import DEFAULT_BINARY


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', action='store_true', help='Execute JavaScript, including V8 initialization')
    options = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='retroos-code-host-') as directory:
        work = Path(directory)
        home = work / 'c'
        (home / 'RETROOS').mkdir(parents=True)
        shutil.copyfile(ROOT / 'etc/RETROOS.INI', home / 'RETROOS/RETROOS.INI')
        binary = DEFAULT_BINARY.with_name('codex-code-mode-host').resolve(strict=True)
        command = shlex.quote(str(binary)) + ' --help'
        if options.runtime:
            # Protocol V1: keep stdin open until the execution has settled.
            # Immediate EOF cancels outstanding operations and can falsely
            # make a host which cannot initialize V8 appear to succeed.
            messages = [
                dict(type='connection/hello', supportedVersions=[1], requiredCapabilities=[], optionalCapabilities=[]),
                dict(type='operation/request', id=1, request=dict(method='session/open', sessionId='probe')),
                dict(type='operation/request', id=2, request=dict(method='session/execute', sessionId='probe', request=dict(
                    tool_call_id='probe', enabled_tools=[], source='text("RUNTIME_PASS")',
                    yield_time_ms=1000, max_output_tokens=100))),
            ]
            with (home / 'input').open('wb') as stream:
                for message in messages:
                    payload = json.dumps(message).encode()
                    stream.write(struct.pack('<I', len(payload)) + payload)
            (home / 'producer.sh').write_text('/bin/cat /home/retroos/input\n/bin/sleep 15\n')
            command = '/bin/sh /home/retroos/producer.sh | ' + shlex.quote(str(binary))
        (home / 'run.sh').write_text(command +
            ' > /home/retroos/output 2> /home/retroos/errors\n' + ('exit 0\n' if options.runtime else 'exit $?\n'))
        (work / 'profile.json').write_text(json.dumps({'root': '/', 'c_root': str(home)}))
        label = 'code-mode-host-runtime' if options.runtime else 'code-mode-host'
        launch(work, 'RETROOS/SHELL.ELF /home/retroos/run.sh', label, memory=2048)
        output = (home / 'output').read_bytes()
        if options.runtime:
            errors = (home / 'errors').read_text(errors='replace')
            (ROOT / 'build/ci/code-mode-host-runtime.errors.txt').write_text(errors)
            responses = []
            while output:
                assert len(output) >= 4, 'Truncated protocol frame'
                length = struct.unpack('<I', output[:4])[0]
                assert len(output) >= 4 + length, 'Truncated protocol payload'
                responses.append(json.loads(output[4:4 + length]))
                output = output[4 + length:]
            passed = False
            for message in responses:
                if message.get('type') != 'execute/initialResponse':
                    continue
                result = message.get('result', {})
                value = result.get('value', {}).get('Result', {})
                if result.get('status') == 'ok' and value.get('error_text') is None:
                    passed |= any(item.get('text') == 'RUNTIME_PASS'
                        for item in value.get('content_items', []))
            assert passed, 'JavaScript did not execute; see build/ci/code-mode-host-runtime.errors.txt: ' + errors[:500]
        else:
            assert b'Usage: codex-code-mode-host' in output
    print('PASS: native code-mode host ' + ('executes JavaScript' if options.runtime else 'loads and runs through shell fork/exec'))


if __name__ == '__main__':
    main()
