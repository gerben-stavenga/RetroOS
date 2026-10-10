#!/usr/bin/env python3
"""Disk showcase seeding preserves existing user data and symlink directories."""
from pathlib import Path
import sys
import tempfile
import tarfile
import json
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import machine_install as installer


class ShowcaseTests(unittest.TestCase):
    def test_seed_preserves_files_and_links_and_can_repeat(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / 'showcase'
            (source / 'GAMES/OWN').mkdir(parents=True)
            (source / 'GAMES/OWN/CFG').write_text('default')
            (source / 'GAMES/OWN/NEW').write_text('new')
            (source / 'GAMES/OWN/NEW').chmod(0o444)
            (source / 'GAMES/LINK').mkdir()
            (source / 'GAMES/LINK/NEW').write_text('do not write through')
            target = root / 'C'
            (target / 'GAMES/OWN').mkdir(parents=True)
            (target / 'GAMES/OWN/CFG').write_text('user settings')
            other = root / 'other'
            other.mkdir()
            (target / 'GAMES/LINK').symlink_to(other)
            self.assertEqual(installer.copy_showcase_tree(source, target), 1)
            self.assertEqual((target / 'GAMES/OWN/CFG').read_text(), 'user settings')
            self.assertEqual((target / 'GAMES/OWN/NEW').read_text(), 'new')
            self.assertFalse((other / 'NEW').exists())
            self.assertEqual((target / 'GAMES/OWN/NEW').stat().st_mode & 0o777, 0o644)
            self.assertEqual(installer.copy_showcase_tree(source, target), 0)

    def test_prepare_stages_optional_files_outside_runtime(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            core = root / 'core'
            (core / 'RETROOS').mkdir(parents=True)
            (core / 'RETROOS/RETROOS.INI').write_text('[system]\nstart=C:\\DN\\DN.COM\n')
            archive = root / 'core.tar'
            with tarfile.open(archive, 'w') as tar:
                tar.add(core / 'RETROOS', arcname='RETROOS')
            optional = root / 'optional'
            (optional / 'GAMES').mkdir(parents=True)
            (optional / 'GAMES/OWN.DAT').write_text('game')
            showcase = root / 'showcase.tar'
            with tarfile.open(showcase, 'w') as tar:
                tar.add(optional / 'GAMES', arcname='GAMES')
            with patch.object(installer, 'STAGE', root / 'stage'), \
                 patch.object(installer, 'validate', return_value='test-uuid'):
                installer.prepare(root / 'C', root / 'boot', archive, True, showcase)
                stage = Path((root / 'stage/selected').read_text().strip())
                self.assertTrue((stage / 'showcase/GAMES/OWN.DAT').is_file())
                self.assertFalse((stage / 'runtime/GAMES').exists())
                self.assertFalse((root / 'C').exists())
                self.assertTrue(json.loads((stage / 'plan.json').read_text())['copy_showcase'])
                self.assertIn('showcase/GAMES/OWN.DAT', json.loads((stage / 'checksums.json').read_text()))
                installer.prepare(root / 'C', root / 'boot', archive, False)
                stage = Path((root / 'stage/selected').read_text().strip())
                self.assertFalse((stage / 'showcase').exists())
                self.assertFalse(json.loads((stage / 'plan.json').read_text())['copy_showcase'])

    def test_prepare_choice_and_noninteractive_default(self):
        for flags, exists, terminal, answer, expected in [
            ([], False, True, 'yes', True), ([], False, True, 'no', False),
            ([], False, False, None, False), ([], True, True, None, False),
            ([], True, False, None, False),
            (['--copy-showcase'], True, True, None, True),
            (['--copy-showcase'], False, False, None, True),
            (['--no-copy-showcase'], False, True, None, False),
        ]:
            with tempfile.TemporaryDirectory() as folder:
                c_root = Path(folder) / 'C'
                if exists:
                    c_root.mkdir()
                with self.subTest(flags=flags, exists=exists, terminal=terminal), \
                     patch.object(sys, 'argv', ['machine_install', '--prepare', '--c-root', str(c_root)] + flags), \
                     patch.object(sys.stdin, 'isatty', return_value=terminal), \
                     patch('builtins.input', return_value=answer) as prompt, \
                     patch.object(installer, 'prepare') as prepare:
                    installer.main()
                    self.assertEqual(prepare.call_args.args[3], expected)
                    self.assertEqual(prompt.called, not exists and terminal and not flags)



if __name__ == '__main__':
    unittest.main()
