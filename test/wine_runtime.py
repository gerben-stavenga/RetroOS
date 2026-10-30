"""Install the same Windows runtime used by the boot image into a test drive."""
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parent.parent
TARGET = "//lib/wine:runtime"


def install(root):
    with tarfile.open(ROOT / "bazel-bin/lib/wine/runtime.tar") as archive:
        archive.extractall(root, filter="data")
