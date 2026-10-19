#!/usr/bin/env python3
"""Run native Bazel and a fresh genrule inside QEMU/KVM running RetroOS."""
import argparse
from pathlib import Path
import subprocess
import shlex
import uuid

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--install-base', type=Path, help='Already extracted native Bazel runtime')
    parser.add_argument('--timeout', type=int, default=240)
    args = parser.parse_args()
    install = args.install_base
    if install is None:
        install = Path(subprocess.check_output(['bazelisk', 'info', 'install_base'], cwd=ROOT, text=True).strip())
    work = ROOT / 'build/ci/bazel-smoke'
    workspace = ROOT / 'build/ci/bazel-smoke-workspace'
    workspace.mkdir(parents=True, exist_ok=True)
    for index in range(96):
        leaf = workspace / 'walk' / f'directory{index:03}' / 'nested'
        leaf.mkdir(parents=True, exist_ok=True)
        (leaf / 'input.txt').write_text(f'glob input {index}\n')
    (workspace / 'WORKSPACE').write_text('workspace(name="retroos_bazel_smoke")\n')
    (workspace / '.bazelrc').write_text('build --workspace_status_command=' +
        shlex.quote(str(ROOT / 'tools/workspace_status.sh')) + '\n')
    output = '/'.join([f'output{index}_' + 'x' * 64 for index in range(4)] + ['hello.txt'])
    (workspace / 'BUILD').write_text(
        'genrule(name="hello", srcs=["request.txt"] + glob(["walk/**/*.txt"]), '
        f'outs=["{output}", "version.txt", "manifest.txt"], stamp=1, '
        f'cmd="cat $(location request.txt) > $(location {output}) '
        '&& cat bazel-out/stable-status.txt > $(location version.txt) '
        '&& printf \'%s\\n\' $(SRCS) > $(location manifest.txt)")\n')
    # A unique declared input forces actual tool execution on every run.
    expected = ('built inside RetroOS ' + uuid.uuid4().hex + '\n').encode()
    (workspace / 'request.txt').write_bytes(expected)
    subprocess.run(['python3', str(ROOT / 'tools/try_self_build.py'), '//:hello',
        '--work-dir', str(work), '--workspace', str(workspace), '--install-base', str(install), '--timeout', str(args.timeout),
        '--bazel-arg=--enable_bzlmod=false'], cwd=ROOT, check=True)
    outputs = (work / 'c/cache').glob(
        '*/execroot/retroos_bazel_smoke/bazel-out/*/bin/' + output)
    assert any(path.read_bytes() == expected for path in outputs), 'Guest output differs from the fresh input'
    versions = (work / 'c/cache').glob(
        '*/execroot/retroos_bazel_smoke/bazel-out/*/bin/version.txt')
    stamps = [path.read_text() for path in versions]
    assert any('STABLE_RETROOS_GIT_DESCRIBE ' in stamp and
               'STABLE_RETROOS_GIT_DESCRIBE unknown' not in stamp for stamp in stamps), stamps
    manifests = (work / 'c/cache').glob(
        '*/execroot/retroos_bazel_smoke/bazel-out/*/bin/manifest.txt')
    expected_sources = {'request.txt'} | {
        f'walk/directory{index:03}/nested/input.txt' for index in range(96)}
    assert any(set(path.read_text().splitlines()) == expected_sources for path in manifests), 'Recursive glob lost input files'
    print('PASS: guest Bazel built a fresh genrule with a deep output path, traversed 96 nested directories and obtained the Git version stamp')


if __name__ == '__main__':
    main()
