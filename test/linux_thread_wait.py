#!/usr/bin/env python3
"""Verify blocking child waits park individual Linux user threads."""
from linux_time_high import main
if __name__ == '__main__':
    main('linux_thread_wait_probe.c', 'THREAD_WAIT_PASS:', 'linux-thread-wait')
