import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('release_notes', Path(__file__).resolve().parents[1] / 'tools/release_notes.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ReleaseNotesTest(unittest.TestCase):
    def test_selects_only_requested_version(self):
        changelog = '# Changelog\n\n## [Unreleased]\nFuture changes.\n\n## [0.8.0] - 2026-10-08\n\n### Added\nDOS support.\n\n## [0.7.0] - 2026-09-01\nOld changes.\n'
        version, pre, notes = module.release_notes('v0.8.0', changelog)
        self.assertEqual(version, '0.8.0')
        self.assertFalse(pre)
        self.assertEqual(notes, '### Added\nDOS support.\n')

    def test_prerelease_with_build_metadata(self):
        version, pre, notes = module.release_notes('v0.8.0-rc.1+build.3', '## [0.8.0-rc.1+build.3] - 2026-10-08\nCandidate.\n')
        self.assertTrue(pre)
        self.assertEqual(version, '0.8.0-rc.1+build.3')

    def test_rejects_invalid_and_unreviewed_releases(self):
        for tag in ['retroos', 'v01.8.0', '0.8.0', 'v0.8', 'v0.8.0-rc.01', 'v0.8.0/other']:
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                module.release_notes(tag, '## [0.8.0] - 2026-10-08\nChanges.\n')
        for changelog in ['', '## [0.8.0]\nChanges.', '## [0.8.0] - 2026-02-30\nChanges.', '## [0.8.0] - 2026-10-08\n', '## [0.8.0] - 2026-10-08\nOne\n## [0.8.0] - 2026-10-08\nTwo']:
            with self.subTest(changelog=changelog), self.assertRaises(ValueError):
                module.release_notes('v0.8.0', changelog)
