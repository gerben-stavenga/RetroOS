import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "startup", Path(__file__).resolve().parents[1] / "tools/rust_dos_startup.py")
startup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(startup)


class StartupTest(unittest.TestCase):
    def test_unix_program_path_uses_game_directory_and_preserves_arguments(self):
        self.assertEqual(startup.startup_lines("GAMES/DOOMS/DOOM.EXE -timedemo demo1 /flag"),
                         ['CD GAMES\\DOOMS', 'DOOM.EXE -timedemo demo1 /flag'])

    def test_absolute_dos_path_selects_drive(self):
        self.assertEqual(startup.startup_lines(r"C:\GAMES\KEEN1\KEEN1.EXE"),
                         ["C:", 'CD C:\\GAMES\\KEEN1', "KEEN1.EXE"])

    def test_quoted_path_and_arguments_keep_their_quotes(self):
        self.assertEqual(startup.startup_lines('"GAMES/Long Dir/My Game.exe" "argument with spaces"'),
                         ['CD GAMES\\Long Dir', '"My Game.exe" "argument with spaces"'])

    def test_root_program_and_builtins(self):
        self.assertEqual(startup.startup_lines("/GAME.EXE"), ['CD \\', "GAME.EXE"])
        self.assertEqual(startup.startup_lines("dir GAMES"), ["dir GAMES"])

    def test_explicit_dos_script_is_preserved(self):
        self.assertEqual(startup.startup_lines("cd GAMES\\KEEN1\r\nKEEN1\r\n"),
                         ["cd GAMES\\KEEN1", "KEEN1"])


if __name__ == "__main__":
    unittest.main()
