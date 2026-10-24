"""Harness regression tests: malformed captures and false-pass prevention."""

import argparse
from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("game_suite", Path(__file__).with_name("game_suite.py"))
suite = importlib.util.module_from_spec(spec)
spec.loader.exec_module(suite)


def picture(pixels):
    return b"P6\n2 2\n255\n" + bytes(pixels)


def wav(samples):
    payload = struct.pack("<" + "h" * len(samples), *samples)
    return (b"RIFF" + struct.pack("<I", 36 + len(payload)) + b"WAVEfmt "
            + struct.pack("<IHHIIHH", 16, 1, 2, 22050, 88200, 4, 16)
            + b"data" + struct.pack("<I", 0) + payload)


class CaptureTest(unittest.TestCase):
    def test_rejects_truncated_frames_and_accepts_whitespace_pixel(self):
        data = picture([10] + [0] * 11)
        self.assertEqual(suite.ppm(data)[2][0], 10)
        for bad in (b"", data[:-1], data + b"x", b"P6\n0 0\n255\n"):
            with self.subTest(bad=bad), self.assertRaises(suite.Failure):
                suite.ppm(bad)

    def test_comparison_counts_pixels_and_respects_tolerance(self):
        expected = picture([0] * 12)
        self.assertEqual(suite.picture_difference(picture([16] * 12), expected), 0)
        self.assertEqual(suite.picture_difference(picture([17] + [0] * 11), expected), 0.25)
        with self.assertRaises(suite.Failure):
            suite.picture_difference(b"P6\n1 4\n255\n" + bytes(12), expected)

    def test_audio_includes_unpatched_tail_and_detects_silence(self):
        self.assertEqual(suite.audio_stats(wav([0, 0, -32768, 1]))["peak"], 32768)
        self.assertEqual(suite.audio_stats(wav([0, 0]))["peak"], 0)
        self.assertEqual(suite.audio_stats(wav([]))["seconds"], 0)
        with self.assertRaises(suite.Failure):
            suite.audio_stats(b"")

    def test_catalog_rejects_path_escape_and_duplicate_ids(self):
        with tempfile.TemporaryDirectory() as work:
            path = Path(work) / "catalog.json"
            case = {"id": "test", "directory": "GAMES/TEST", "executable": "TEST.COM",
                    "steps": [{"op": "wait", "seconds": 0}]}
            for cases in ([case, case], [{**case, "directory": "../outside"}],
                          [{**case, "steps": [{"op": "key", "key": "TYPO"}]}]):
                path.write_text(json.dumps(cases))
                with self.assertRaises(ValueError):
                    suite.load_catalog(path)


class MachineTest(unittest.TestCase):
    def test_log_flood_does_not_block_guest_and_deadline_still_applies(self):
        import sys
        with tempfile.TemporaryDirectory() as work:
            machine = suite.Machine([sys.executable, "-u", "-c",
                                     "import time; print('x'*200000); print('ready'); time.sleep(30)"],
                                    Path(work), 0.5)
            try:
                machine.wait_for(lambda: b"ready" in suite.read(machine.log_path), 0.4, "ready")
                with self.assertRaisesRegex(suite.Failure, "deadline"):
                    machine.wait(1)
            finally:
                machine.close()
            self.assertIsNotNone(machine.process.poll())

    def test_zero_exit_and_panics_cannot_pass_as_running_games(self):
        import sys
        for script, reason in (("pass", "exited early"),
                               ("import time; print('KERNEL PANIC', flush=True); time.sleep(30)", "PANIC")):
            with self.subTest(script=script), tempfile.TemporaryDirectory() as work:
                machine = suite.Machine([sys.executable, "-u", "-c", script], Path(work), 2)
                try:
                    with self.assertRaisesRegex(suite.Failure, reason):
                        machine.wait(0.3)
                finally:
                    machine.close()

    def test_failed_case_cannot_replace_golden_and_retains_drive(self):
        # Fake a graphics-producing hosted binary. The picture checkpoint
        # succeeds, then a required marker fails. Bless must be transactional
        # across the scenario, and the source must remain unchanged.
        with tempfile.TemporaryDirectory() as work:
            root = Path(work)
            game = root / "source/GAMES/TEST"
            game.mkdir(parents=True)
            (game / "TEST.COM").write_bytes(b"source")
            fake = root / "host"
            fake.write_text("#!/usr/bin/env python3\nimport sys,time\nfrom pathlib import Path\n"
                            "p=Path(sys.argv[sys.argv.index('--screenshot')+1]+'.ppm')\n"
                            "p.write_bytes(b'P6\\n2 2\\n255\\n'+bytes([255,0,0]*4))\n"
                            "print('event_loop entered',flush=True)\ntime.sleep(30)\n")
            fake.chmod(0o755)
            golden = root / "golden/tcg/test/picture.ppm"
            golden.parent.mkdir(parents=True)
            golden.write_bytes(b"old reference")
            output = root / "out"
            output.mkdir()
            args = argparse.Namespace(source=root / "source", host_bin=fake, output=output,
                                      engine="tcg", golden=root / "golden", bless=True, compare=False,
                                      storage="disk")
            case = {"id": "test", "directory": "GAMES/TEST", "executable": "TEST.COM",
                    "files": {"TEST.COM": "private copy"}, "timeout": 3,
                    "steps": [{"op": "shot", "name": "picture", "settle": 0,
                               "min_colours": 1},
                              {"op": "log", "contains": "missing", "timeout": 0.1}]}
            with redirect_stdout(io.StringIO()):
                result = suite.run_case(case, args)
            self.assertEqual(result["status"], "fail")
            self.assertIn("missing", result["error"])
            self.assertEqual(golden.read_bytes(), b"old reference")
            self.assertEqual((game / "TEST.COM").read_bytes(), b"source")
            self.assertEqual((output / "test/c/GAMES/TEST/TEST.COM").read_text(), "private copy")
            self.assertTrue((output / "test/picture.ppm").is_file())
            for name, marker, steps, expected in (
                ("known", "timed out waiting for log: missing", case["steps"], "known-fail"),
                ("unrelated", "a different failure", case["steps"], "fail"),
                ("fixed", "timed out waiting for log: missing", case["steps"][:1], "unexpected-pass"),
            ):
                with self.subTest(name=name):
                    marked = {**case, "id": name, "steps": steps, "expect_failure": marker}
                    with redirect_stdout(io.StringIO()):
                        result = suite.run_case(marked, args)
                    self.assertEqual(result["status"], expected)
                    self.assertFalse((root / "golden/tcg" / name / "picture.ppm").exists())


if __name__ == "__main__":
    unittest.main()
