#!/usr/bin/env python3
"""Deliver real Set-1 input through Wine's message queue and TranslateMessage."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from game_suite import Failure
from rustdos_suite import Machine as BaseMachine
from wine_runtime import install, ROOT

class Machine(BaseMachine):
    def check(self, allow_exit=False):
        log=self.log_path.read_text(errors='replace')
        for marker in ('KERNEL PANIC','panicked at','!!! FATAL !!!','Unhandled exception','SEGV','not implemented','KEY FAIL','KEY CHECK FAILED'):
            if marker in log:raise Failure('log contains '+marker)
        code=self.process.poll()
        if code is not None and (not allow_exit or code):raise Failure(f'guest exited (status {code})')
        if time.monotonic()>=self.deadline:raise Failure('scenario deadline exceeded')

def main():
    engine=os.environ.get('ENGINE','kvm')
    if engine not in ('kvm','tcg'):raise SystemExit('ENGINE must be kvm or tcg')
    win16=os.environ.get('WIN16')=='1'
    target='win16:keyboard' if win16 else 'callbacks:wine_keyboard'
    host='retroos-host-kvm' if engine=='kvm' else 'retroos-host'
    subprocess.run(['bazelisk','build',f'//kernel:{host}','//lib/wine:runtime','//test/windows/'+target,'--platforms=@platforms//host'],cwd=ROOT,check=True)
    with tempfile.TemporaryDirectory(prefix='retroos-wine-keyboard-') as directory:
        work=Path(directory);root=work/'root';root.mkdir();install(root)
        shutil.copyfile(ROOT/('bazel-bin/test/windows/'+target.replace(':','/')+'.exe'),root/'KEY.EXE')
        m=Machine(['python3',str(ROOT/'test/disk_fixture.py'),'--root',str(root),'--',str(ROOT/'bazel-bin/kernel'/host),'--input-control','--c-root','/','--cmd','/KEY.EXE'],work,90)
        try:
            for _ in range(240):
                m.run(250)
                if 'KEY READY' in m.log_path.read_text():break
            else:raise AssertionError(m.log_path.read_text())
            # Make/repeat/break, Shift+A, enhanced cursor, and Enter.
            for codes in (['1e 9e'] if win16 else ['1e','1e','9e','2a 1e','9e aa','e0 48 e0 c8','1c 9c']):
                m.command('scan '+codes);m.run(100)
            for _ in range(80):
                log=m.log_path.read_text()
                if 'KEY PASS' in log or 'KEY FAIL' in log:break
                m.run(100)
            assert 'KEY PASS' in log and 'KEY CHECK FAILED' not in log, log
        except Exception as error:
            raise AssertionError(m.log_path.read_text()) from error
        finally:m.close()
    print(f'PASS: Wine keyboard delivery and character translation ({engine}, Win{16 if win16 else 32})')
if __name__=='__main__':main()
