#!/usr/bin/env python3
"""Boot a private Python root with no diagnostic UART and test local MCP."""
import re
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from boot_fixture import ROOT, prepare_boot


def main():
    with tempfile.TemporaryDirectory(prefix='retroos-local-control-') as directory:
        work = Path(directory)
        tree = work / 'root'
        (tree / 'home/retroos/RETROOS').mkdir(parents=True)
        copied = set()
        def copy(source):
            source = Path(source)
            if str(source) in copied or not source.is_file():
                return
            copied.add(str(source))
            target = tree / str(source).lstrip('/')
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        shutil.copytree('/usr/lib/python3.12', tree / 'usr/lib/python3.12',
                        ignore=shutil.ignore_patterns('__pycache__', 'test', 'tests'))
        for binary in ['/usr/bin/python3', *map(str, Path('/usr/lib/python3.12/lib-dynload').glob('*.so'))]:
            copy(binary)
            deps = subprocess.run(['ldd', binary], capture_output=True, text=True, check=True)
            for name in re.findall(r'(/[^\s()]+)', deps.stdout):
                copy(name)
        shutil.copyfile(ROOT / 'tools/86box_mcp.py', tree / '86box_mcp.py')
        for module in ('profile_report.py', 'syscall_names.py'):
            shutil.copyfile(ROOT / 'tools' / module, tree / module)
        shutil.copyfile(ROOT / 'test/linux_local_control_probe.py', tree / 'probe.py')
        data = work / 'data.ext4'
        with data.open('wb') as output:
            output.truncate(256 * 1024 * 1024)
        subprocess.run(['mkfs.ext4', '-q', '-F', '-d', str(tree), str(data)], check=True)
        # Match a metal installation whose configured session home belongs to
        # an ordinary Linux user, rather than accidentally testing only uid 0.
        for field in ('uid', 'gid'):
            subprocess.run(['debugfs', '-w', '-R', f'set_inode_field /home/retroos {field} 1001', str(data)],
                           check=True, capture_output=True)
        boot = prepare_boot(work, data, '[environment]\nTEST=/usr/bin/python3 /probe.py\n')
        log = ROOT / 'build/ci/linux-local-control.log'
        log.parent.mkdir(parents=True, exist_ok=True)
        with log.open('w') as output:
            result = subprocess.run(['qemu-system-x86_64', '-accel', 'kvm', '-cpu', 'host',
                '-m', '1024', '-display', 'none', '-serial', 'none', '-no-reboot', '-nic', 'none',
                '-debugcon', 'stdio', '-drive', f'file={boot},format=raw,snapshot=on',
                '-drive', f'file={data},format=raw'],
                stdout=output, stderr=subprocess.STDOUT, timeout=90)
        text = log.read_text()
        assert result.returncode == 0 and 'LOCAL_CONTROL_PASS:' in text and '[mem] exit tid=1 code=0' in text, text[-5000:]
        assert 'serial-control:' not in text
        report = subprocess.run(['debugfs', '-R', 'cat /home/retroos/capture.json', str(data)], capture_output=True, text=True)
        import json
        capture = json.loads(report.stdout)
        assert capture['quality']['valid'], capture['quality']
        artifacts = Path(os.environ.get('TEST_UNDECLARED_OUTPUTS_DIR', ROOT / 'build/ci'))
        artifacts.mkdir(parents=True, exist_ok=True)
        (artifacts / 'local-control-capture.json').write_text(json.dumps(capture, indent=2)+'\n')
        print('PROFILE_RECONCILIATION:', json.dumps(capture['quality']['signed_alignment_errors_ns']),
              'window_ns=', capture['window']['elapsed_ns'], 'tolerance_ns=', capture['quality']['tolerance_ns'])
        print('PASS: in-guest local MCP without a COM2 connection')


if __name__ == '__main__':
    main()
