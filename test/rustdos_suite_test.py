"""Catalog fidelity and replay regressions, independent of game downloads."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rustdos_suite as suite

spec = importlib.util.spec_from_file_location("catalog_export", suite.ROOT / "tools/import_rustdos_suite.py")
exporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exporter)


class CatalogTest(unittest.TestCase):
    def test_generated_catalog_exactly_matches_upstream_source(self):
        catalog = json.loads(suite.CATALOG.read_text())
        self.assertEqual(exporter.export(), catalog)
        self.assertEqual(len(catalog["scenarios"]), 72)
        self.assertEqual(len(catalog["games"]), 16)
        self.assertEqual({g["id"] for g in catalog["games"]}, {
            "doom", "heretic", "duke3d", "descent", "raptor", "wolf3d", "wolf3d-original",
            "keen1", "jill", "cosmo", "duke1", "scorch", "alleycat", "digger", "sopwith", "rogue"})

    def test_exporter_never_evaluates_arbitrary_python(self):
        for expression in ("__import__('os').system('false')", "Unknown(1)", "[x for x in []]"):
            with self.subTest(expression=expression), self.assertRaises(ValueError):
                exporter.debug_value(expression)
        self.assertEqual(exporter.debug_value('Not(Text("quit?"))'),
                         {"kind": "Not", "args": [{"kind": "Text", "args": ["quit?"]}]})

    def test_every_catalog_key_and_character_has_an_input_mapping(self):
        def visit(step):
            kind, args = step["kind"], step["args"]
            if kind in {"Key", "Hold", "PressUntil"}:
                self.assertIn(args[0], suite.SCAN)
            elif kind == "Keys":
                for key in args[0]: self.assertIn(key, suite.SCAN)
            elif kind == "Type":
                for character in args[0]:
                    key = {"\n": "enter", " ": "space"}.get(character.lower(), character.lower())
                    self.assertIn(key, suite.SCAN)
        catalog = json.loads(suite.CATALOG.read_text())
        for case in catalog["scenarios"]:
            for step in case["steps"]: visit(step)
        for game in catalog["games"]:
            for step in game["install"].get("steps", []): visit(step)

    def test_configuration_gaps_are_explicit(self):
        catalog = json.loads(suite.CATALOG.read_text())
        network = next(c for c in catalog["scenarios"] if c["name"] == "doom/net-ipx")
        self.assertTrue(any("two-machine" in gap for gap in suite.deviations(network)))
        dynamic = next(c for c in catalog["scenarios"] if c["name"] == "keen1/ega-3000-dynamic")
        self.assertTrue(any("dynamic-recompiler" in gap for gap in suite.deviations(dynamic)))
        self.assertTrue(any("CPU model 386" in gap for gap in suite.deviations(dynamic)))
        supported = next(c for c in catalog["scenarios"] if c["name"] == "keen1/vga-20000")
        self.assertEqual(suite.deviations(supported), [])


class ScriptTest(unittest.TestCase):
    def test_holds_and_speed_changes_remain_distinct_from_taps(self):
        class FakeMachine:
            ms = 0
            calls = []
            def run(self, ms): self.calls.append(("run", ms)); self.ms += ms
            def press(self, *args): self.calls.append(("press", *args))
            def command(self, command): self.calls.append(("command", command))
            def type_text(self, text): self.calls.append(("type", text))
            def condition(self, condition): return True
        fake = FakeMachine()
        steps = [exporter.debug_value(value) for value in (
            'Cycles(300)', 'Wait(1000)', 'Hold("up", 1500)', 'Key("ctrl")',
            'Keys(["enter", "escape"], 300)', 'Type("TEST\\n")', 'Check(Running)')]
        with tempfile.TemporaryDirectory() as work:
            suite.replay(fake, steps, Path(work))
        self.assertEqual(fake.calls, [("command", "cycles 300"), ("run", 1000),
            ("press", "up", 1500, 60), ("press", "ctrl"), ("press", "enter", 60, 240),
            ("press", "escape", 60, 240), ("type", "TEST\n")])

    def test_conditions_cannot_be_ignored(self):
        class FakeMachine:
            ms = 123
            def condition(self, condition): return False
        with tempfile.TemporaryDirectory() as work:
            with self.assertRaisesRegex(suite.common.Failure, "step 0 Check.*condition failed"):
                suite.replay(FakeMachine(), [exporter.debug_value('Check(Running)')], Path(work))


if __name__ == "__main__":
    unittest.main()
