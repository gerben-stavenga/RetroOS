#!/usr/bin/env python3
"""Node/V8 must survive heap-page discard during repeated full collections."""
import json
from pathlib import Path
import shutil
import tempfile
from linux_smb_symlink import ROOT, launch


def main():
    with tempfile.TemporaryDirectory(prefix='retroos-node-gc-') as directory:
        work = Path(directory)
        home = work / 'c'
        (home / 'RETROOS').mkdir(parents=True)
        shutil.copyfile(ROOT / 'etc/RETROOS.INI', home / 'RETROOS/RETROOS.INI')
        (work / 'profile.json').write_text(json.dumps({'root': '/', 'c_root': str(home)}))
        (home / 'gc.js').write_text('''
const kept = Array.from({length: 10000}, (_, i) => ({i, text: 'kept'.repeat(16)}));
const survivors = [];
for (let round = 0; round < 8; round++) {
    let garbage = Array.from({length: 20000}, (_, i) => new Array(256).fill(i));
    global.gc(); // Promote the arrays while they are still live.
    for (let i = 0; i < garbage.length; i += 64) survivors.push(garbage[i]);
    garbage = null;
    global.gc(); // Leave page-sized holes between retained old-space arrays.
}
if (kept[9999].i !== 9999 || kept[0].text !== 'kept'.repeat(16)) process.exit(2);
if (survivors[1][0] !== 64 || survivors[1][255] !== 64) process.exit(3);
console.log('NODE GC PASS');
''')
        (home / 'run.sh').write_text(
            '/usr/bin/node --max-old-space-size=96 --no-compact --expose-gc /home/retroos/gc.js > /home/retroos/output 2> /home/retroos/errors\n'
            'exit $?\n')
        launch(work, 'RETROOS/SHELL.ELF /home/retroos/run.sh', 'linux-node-gc', timeout=180, memory=2048)
        assert (home / 'output').read_text().strip() == 'NODE GC PASS'
    print('PASS: Node/V8 full collections discard pages and preserve live objects')


if __name__ == '__main__':
    main()
