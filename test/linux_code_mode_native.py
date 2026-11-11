#!/usr/bin/env python3
"""Execute JavaScript in the managed code-mode host with 96 inherited fds."""
from pathlib import Path
import argparse
import json
import shutil
import struct
import subprocess
import native_program_profile
from linux_smb_symlink import ROOT

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=Path.home() / '.codex/packages/app-server-daemon/current/bin/codex-code-mode-host')
    options = parser.parse_args()
    label = 'code-mode-native-fds'
    work = ROOT / 'build/ci' / label
    home = work / 'c'
    for child in ('RETROOS', 'TEMP'):
        (home / child).mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / 'etc/RETROOS.INI', home / 'RETROOS/RETROOS.INI')
    binary = options.binary.resolve(strict=True)
    (work / 'binary.txt').write_text(str(binary) + '\n')
    subprocess.run(['gcc', '-m64', '-nostdlib', '-static', '-no-pie', '-fno-pie', '-fno-stack-protector', '-O2',
        '-DCODE_HOST_PATH=' + json.dumps(str(binary)), str(ROOT / 'test/linux_fd_limits_probe.c'), '-o', str(home / 'pressure')], check=True)
    messages = [dict(type='connection/hello', supportedVersions=[1], requiredCapabilities=[], optionalCapabilities=[]),
        dict(type='operation/request', id=1, request=dict(method='session/open', sessionId='probe')),
        dict(type='operation/request', id=2, request=dict(method='session/execute', sessionId='probe', request=dict(
            tool_call_id='probe', enabled_tools=[], source="text('NATIVE_CODE_HOST_PASS')", yield_time_ms=1000, max_output_tokens=100)))]
    with (home / 'input').open('wb') as stream:
        for message in messages:
            data = json.dumps(message).encode();stream.write(struct.pack('<I',len(data))+data)
    (home / 'producer.sh').write_text('/bin/cat /home/retroos/input\n/bin/sleep 15\n')
    (home / 'run.sh').write_text('/bin/sh /home/retroos/producer.sh | /home/retroos/pressure > /home/retroos/output-runtime 2> /home/retroos/errors-runtime\nexit $?\n')
    image = native_program_profile.prepare(work, home, True, [str(binary), '/bin/cat', '/bin/sleep'])
    native_program_profile.launch(work, home, image, label, ['runtime'])
    output = (home / 'output-runtime').read_bytes()
    passed = False
    while output:
        assert len(output)>=4
        size=struct.unpack('<I',output[:4])[0];assert len(output)>=size+4
        message=json.loads(output[4:4+size]);output=output[4+size:]
        if message.get('type')=='execute/initialResponse':
            result=message.get('result',{})
            content=result.get('value',{}).get('Result',{}).get('content_items',[])
            passed |= result.get('status')=='ok' and any(item.get('text')=='NATIVE_CODE_HOST_PASS' for item in content)
    assert passed, (home / 'errors-runtime').read_text()[-1500:]
    print('PASS: managed code-mode host executes JavaScript on native ext4 with 96 inherited descriptors')

if __name__=='__main__':main()
