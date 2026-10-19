#!/usr/bin/env python3
"""Native Rust Command::output, including stdout/stderr larger than a pipe ring."""
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
from linux_smb_symlink import ROOT, launch


def main():
    with tempfile.TemporaryDirectory(prefix='retroos-process-output-') as directory:
        work = Path(directory)
        home = work / 'c'
        (home / 'RETROOS').mkdir(parents=True)
        shutil.copyfile(ROOT / 'etc/RETROOS.INI', home / 'RETROOS/RETROOS.INI')
        (work / 'profile.json').write_text(json.dumps({'root': '/', 'c_root': str(home)}))
        subprocess.run(['rustc', '--edition=2024', '-C', 'target-feature=+crt-static',
                        '-C', 'relocation-model=static',
                        str(ROOT / 'test/linux_process_output_probe.rs'), '-o', str(home / 'probe')], check=True)
        launch(work, 'probe', 'linux-process-output')
        text = (ROOT / 'build/ci/linux-process-output.log').read_text()
        assert 'RUST PROCESS OUTPUT PASS: 131072 bytes per stream' in text


if __name__ == '__main__':
    main()
