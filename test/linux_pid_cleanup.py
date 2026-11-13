#!/usr/bin/env python3
"""Reaped process-group cleanup must not hit a newly spawned unrelated job."""
from linux_time_high import main

if __name__ == '__main__':
    main('linux_pid_cleanup_probe.c', 'PID_CLEANUP_PASS:', 'linux-pid-cleanup')
