#!/usr/bin/env python3
"""Exercise nested child DCs on Wine's shared top-level drawing surface."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from wine_runtime import install, ROOT


def main():
    engine = os.environ.get("ENGINE", "kvm")
    if engine not in ("kvm", "tcg"):
        raise SystemExit("ENGINE must be kvm or tcg")
    host = "retroos-host-kvm" if engine == "kvm" else "retroos-host"
    subprocess.run(["bazelisk", "build", f"//kernel:{host}", "//lib/wine:runtime",
                    "//test/windows/callbacks:wine_surface", "//test/windows/win16:clipping", "--platforms=@platforms//host"], cwd=ROOT, check=True)
    with tempfile.TemporaryDirectory(prefix="retroos-wine-surface-") as directory:
        root = Path(directory)
        install(root)
        for binary, marker in (("callbacks/wine_surface.exe", "SURFACE PASS"),
                               ("win16/clipping.exe", "WIN16 CLIPPING PASS")):
            shutil.copyfile(ROOT / "bazel-bin/test/windows" / binary, root / "PROBE.EXE")
            run = subprocess.run(["python3", str(ROOT / "test/disk_fixture.py"), "--root", directory,
                                  "--", str(ROOT / "bazel-bin/kernel" / host), "--c-root", "/",
                                  "--cmd", "/PROBE.EXE"], cwd=ROOT, capture_output=True, text=True, timeout=60)
            log = run.stdout + run.stderr
            if run.returncode or marker not in log or any(s in log for s in (" FAIL", "PANIC", "SEGV", "not implemented")):
                raise SystemExit(log)
    print(f"PASS: Wine child surfaces, clipping and Win16 direction-flag boundary ({engine})")


if __name__ == "__main__":
    main()
