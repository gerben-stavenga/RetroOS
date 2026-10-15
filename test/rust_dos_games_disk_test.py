"""The DOS image consumes ordinary files from bundles with Unix symlinks."""
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location(
    "games_disk", Path(__file__).resolve().parents[1] / "tools/build_rust_dos_games_disk.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class ExtractionTest(unittest.TestCase):
    def test_unix_links_do_not_prevent_dos_files_from_being_extracted(self):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w") as archive:
            entry = tarfile.TarInfo("GAMES/TEST/TEST.EXE")
            entry.size = 4
            archive.addfile(entry, io.BytesIO(b"game"))
            for name, target, kind in (("bin/rc", "/COMMANDER/RC/RC.EXE", tarfile.SYMTYPE),
                                       ("bin/sh", "busybox", tarfile.SYMTYPE),
                                       ("bin/alias", "GAMES/TEST/TEST.EXE", tarfile.LNKTYPE)):
                link = tarfile.TarInfo(name)
                link.type = kind
                link.linkname = target
                archive.addfile(link)
        data.seek(0)
        with tempfile.TemporaryDirectory() as work:
            with tarfile.open(fileobj=data) as archive:
                builder.extract_dos_files(archive, work)
            self.assertEqual((Path(work) / "GAMES/TEST/TEST.EXE").read_bytes(), b"game")
            self.assertFalse((Path(work) / "bin").exists())

    def test_regular_file_paths_still_use_the_data_filter(self):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w") as archive:
            entry = tarfile.TarInfo("../outside")
            entry.size = 4
            archive.addfile(entry, io.BytesIO(b"oops"))
        data.seek(0)
        with tempfile.TemporaryDirectory() as work, tarfile.open(fileobj=data) as archive:
            with self.assertRaises(tarfile.FilterError):
                builder.extract_dos_files(archive, work)


if __name__ == "__main__":
    unittest.main()
