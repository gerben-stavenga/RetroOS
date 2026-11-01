#!/usr/bin/env python3
"""Exercise Wine mouse hit-testing, coordinates, capture, and button state."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from wine_keyboard import Machine
from wine_runtime import install, ROOT


def main():
    engine=os.environ.get("ENGINE","kvm")
    if engine not in ("kvm","tcg"):raise SystemExit("ENGINE must be kvm or tcg")
    host="retroos-host-kvm" if engine=="kvm" else "retroos-host"
    subprocess.run(["bazelisk","build",f"//kernel:{host}","//lib/wine:runtime","//test/windows/callbacks:wine_mouse","--platforms=@platforms//host"],cwd=ROOT,check=True)
    with tempfile.TemporaryDirectory(prefix="retroos-wine-mouse-") as directory:
        work=Path(directory);root=work/"root";root.mkdir();install(root)
        shutil.copyfile(ROOT/"bazel-bin/test/windows/callbacks/wine_mouse.exe",root/"MOUSE.EXE")
        m=Machine(["python3",str(ROOT/"test/disk_fixture.py"),"--root",str(root),"--",str(ROOT/"bazel-bin/kernel"/host),"--input-control","--c-root","/","--cmd","/MOUSE.EXE"],work,90)
        def until(marker):
            for _ in range(240):
                if marker in m.log_path.read_text():return
                m.run(250)
            raise AssertionError(m.log_path.read_text())
        try:
            until("MOUSE READY")
            m.command("mouse 43 64 0");m.run(100)
            m.command("mouse 0 0 1");until("MOUSE DOWN")
            m.command("mouse 157 136 1");m.run(100)
            m.command("mouse 0 0 0");until("MOUSE PASS")
            assert "MOUSE FAIL" not in m.log_path.read_text(),m.log_path.read_text()
        except Exception as error:
            raise AssertionError(m.log_path.read_text()) from error
        finally:m.close()
    print(f"PASS: Wine mouse child hit-testing, capture, coordinates and button state ({engine})")


if __name__=="__main__":main()
