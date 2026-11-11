#!/usr/bin/env python3
"""Known-failure repro: Samba cannot unlink hidden native dangling symlinks."""
import argparse
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import threading
import re
from linux_smb_symlink import ROOT, launch


SOURCE = r'''
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#define CHECK(x,n) do { if (!(x)) { dprintf(2,"NATIVE_CLEAN_FAIL %d errno=%d\n",n,errno); return n; } } while (0)
int main(void) {
#ifdef CLEAN_TRACE
    sleep(3);
#endif
    CHECK(unlink("/home/retroos/native-clean/dangling") == 0, 1);
    CHECK(unlink("/home/retroos/native-clean/valid") == 0, 2);
    CHECK(unlink("/home/retroos/native-clean/.lock") == 0, 3);
    CHECK(rmdir("/home/retroos/native-clean") == 0, 4);
    CHECK(unlink("/home/retroos/ordinary") == 0, 5);
    dprintf(2,"NATIVE_CLEAN_PASS\n");
    return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trace',action='store_true')
    options=parser.parse_args()
    for bits in (64, 32):
        with tempfile.TemporaryDirectory(prefix='retroos-smb-native-clean-') as directory:
            work = Path(directory)
            home = work/'c'
            (home/'RETROOS').mkdir(parents=True)
            cleanup = home/'native-clean'
            cleanup.mkdir()
            (cleanup/'dangling').symlink_to(home/'missing-staging/codex')
            (cleanup/'valid').symlink_to(home/'sentinel')
            (cleanup/'.lock').touch()
            (home/'sentinel').write_bytes(b'KEEP_TARGET')
            (home/'ordinary').write_bytes(b'remove')
            shutil.copyfile(ROOT/'etc/RETROOS.INI',home/'RETROOS/RETROOS.INI')
            (work/'profile.json').write_text(json.dumps({'root':'/', 'c_root':str(home)}))
            source = work/'probe.c'
            source.write_text(('#define CLEAN_TRACE\n' if options.trace else '')+SOURCE)
            subprocess.run(['gcc',f'-m{bits}','-static','-O2',str(source),'-o',str(home/'probe')],check=True)
            label = f'smb-native-clean-{bits}'
            stop=threading.Event()
            def trace():
                spec=importlib.util.spec_from_file_location('serial_bridge',ROOT/'tools/86box_mcp.py')
                bridge=importlib.util.module_from_spec(spec)
                spec.loader.exec_module(bridge)
                log=ROOT/'build/ci'/f'{label}.log'
                while not stop.wait(.05):
                    text=log.read_text(errors='replace') if log.exists() else ''
                    match=re.search(r'MCP control: (\S+)',text)
                    if match and 'event_loop entered' in text:
                        control=bridge.SerialControl(None,match.group(1))
                        try:control.request('trace fs')
                        finally:control.close()
                        return
            tracer=threading.Thread(target=trace,daemon=True) if options.trace else None
            if tracer:tracer.start()
            try:launch(work,'probe',label,memory=2048)
            finally:
                stop.set()
                if tracer:tracer.join(timeout=5)
            assert not cleanup.exists(), 'Stale directory was not removed'
            assert not (home/'ordinary').exists()
            assert (home/'sentinel').read_bytes()==b'KEEP_TARGET', 'Unlink followed the native symlink'
            assert 'NATIVE_CLEAN_PASS' in (ROOT/'build/ci'/f'{label}.log').read_text()
    print('PASS: both Linux ABIs remove native dangling/live symlinks and preserve their target')


if __name__ == '__main__':
    main()
