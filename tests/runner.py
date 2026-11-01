#!/usr/bin/env python3
"""Stage declared inputs and run one integration test, without invoking Bazel."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def run(spec, work):
    runfiles = Path(os.environ['TEST_SRCDIR'])
    temporary = work / 'tmp'
    temporary.mkdir()
    for entry in spec['sources']:
        source = runfiles / entry['key']
        destination = work / entry['path']
        destination.parent.mkdir(parents=True, exist_ok=True)
        # Python harnesses find shared fixtures relative to __file__. Copy
        # scripts so resolve() stays inside this test's private workspace.
        if destination.suffix in ('.py', '.sh'):
            shutil.copy2(source, destination)
        else:
            destination.symlink_to(source)
    outputs = work / 'bazel-bin'
    outputs.mkdir()
    for entry in spec['artifacts']:
        if entry['path'].startswith('../'):
            raise ValueError('Declare packaged artifacts instead of external repository paths: ' + entry['path'])
        destination = outputs / entry['path']
        destination.parent.mkdir(parents=True, exist_ok=True)
        source = runfiles / entry['key']
        if destination.is_symlink():
            if destination.resolve() != source.resolve():
                raise ValueError('Conflicting host/metal artifact: ' + entry['path'])
        else:
            destination.symlink_to(source)
    env = os.environ | {
        'TMPDIR': str(temporary),
        'RETROOS_PREBUILT': '1',
        'PYTHONDONTWRITEBYTECODE': '1',
        # The declared harnesses use normal script-relative helper imports.
        'PYTHONSAFEPATH': '',
        'PYTHONPATH': os.pathsep.join([str(work / 'test'), *sys.path]),
        'PATH': str(Path(sys.executable).parent) + os.pathsep + os.environ.get('PATH', ''),
        'RETROOS_TEST_ARTIFACTS': json.dumps({label: [str(outputs / path) for path in paths] for label, paths in spec['targets'].items()}),
    } | spec['env']
    command = spec['command'] + sys.argv[2:]
    if command[0] == 'python3':
        command[0] = sys.executable
    return subprocess.call(command, cwd=work, env=env)


def main():
    spec = json.loads(Path(sys.argv[1]).read_text())
    # QMP Unix sockets have a 108-byte pathname limit. Bazel's sandbox and
    # TEST_TMPDIR prefixes can already exceed it, so allocate a short, private
    # directory for the guest workspace and clean it when the test finishes.
    with tempfile.TemporaryDirectory(prefix='retrotest-', dir='/tmp') as directory:
        return run(spec, Path(directory))


if __name__ == '__main__':
    sys.exit(main())
