#!/usr/bin/env python3
"""Verify timer, user-thread and process progress during clock-read floods."""
from linux_time_high import main
if __name__ == '__main__':
    main('linux_clock_progress_probe.c', 'CLOCK_PROGRESS_PASS:', 'linux-clock-progress')
