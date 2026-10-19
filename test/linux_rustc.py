#!/usr/bin/env python3
"""Compile, link and execute a native Rust program inside RetroOS over SMB."""
import argparse
import json
from pathlib import Path
import shlex
import shutil
import subprocess
from linux_smb_symlink import ROOT, launch


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolchain', type=Path, help='Extracted Linux Rust distribution')
    parser.add_argument('--timeout', type=int, default=360)
    args = parser.parse_args()
    toolchain = args.toolchain
    if toolchain is None:
        output_base = Path(subprocess.check_output(
            ['bazelisk', 'info', 'output_base'], cwd=ROOT, text=True).strip())
        candidates = list((output_base / 'external').glob('*rust_toolchain_x86_64_linux'))
        assert len(candidates) == 1, candidates
        toolchain = candidates[0]
    toolchain = toolchain.resolve(strict=True)
    work = ROOT / 'build/ci/rustc-native'
    home = work / 'c'
    (home / 'RETROOS').mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / 'etc/RETROOS.INI', home / 'RETROOS/RETROOS.INI')
    (work / 'profile.json').write_text(json.dumps({'root': '/', 'c_root': str(home)}))
    (home / 'probe.rs').write_text('fn main() { println!("RUSTC LINK PASS"); }\n')
    for name in ('program', 'status', 'compiler.out', 'compiler.err', 'program.out', 'program.err'):
        (home / name).unlink(missing_ok=True)
    command = [str(toolchain / 'rustc/bin/rustc'), '--edition=2024',
        '--sysroot', str(toolchain / 'rust-std-x86_64-unknown-linux-gnu'),
        '/home/retroos/probe.rs', '-o', '/home/retroos/program']
    (home / 'run.sh').write_text('export MALLOC_ARENA_MAX=2\n' +
        shlex.join(command) + ' > /home/retroos/compiler.out 2> /home/retroos/compiler.err || exit $?\n'
        '/home/retroos/program > /home/retroos/program.out 2> /home/retroos/program.err\n'
        'result=$?\nprintf "%s\\n" "$result" > /home/retroos/status\nexit "$result"\n')
    launch(work, 'RETROOS/SHELL.ELF /home/retroos/run.sh', 'linux-rustc', timeout=args.timeout, memory=2048)
    assert (home / 'program').read_bytes()[:4] == b'\x7fELF', 'Linker output is not ELF'
    assert (home / 'status').read_text().strip() == '0'
    assert (home / 'program.out').read_text() == 'RUSTC LINK PASS\n'
    print('PASS: native Rust compiled, linked a valid ELF and executed it inside RetroOS')


if __name__ == '__main__':
    main()
