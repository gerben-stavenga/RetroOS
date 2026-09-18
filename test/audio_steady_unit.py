#!/usr/bin/env python3
"""Regression checks for the PCM oracle, including deliberately bad output."""
import unittest

from audio_steady import check_pcm


class PcmTests(unittest.TestCase):
    def test_continuous_audio(self):
        check_pcm([100, -100] * 1000, 100, 2, 10)

    def test_silent_output_fails(self):
        with self.assertRaisesRegex(AssertionError, "silent PCM"):
            check_pcm([0] * 2000, 100, 2, 10)

    def test_playback_stalling_after_start_fails(self):
        with self.assertRaisesRegex(AssertionError, "silent PCM"):
            check_pcm([100, -100] * 600 + [0] * 800, 100, 2, 10)

    def test_truncated_output_fails(self):
        with self.assertRaisesRegex(AssertionError, "need 10s"):
            check_pcm([100, -100] * 900, 100, 2, 10)

    def test_boot_silence_is_outside_measured_tail(self):
        check_pcm([0] * 2000 + [100, -100] * 1000, 100, 2, 10)


if __name__ == "__main__":
    unittest.main()
