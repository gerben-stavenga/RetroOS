#!/usr/bin/env python3
"""timerfd under the Linux personality: epoll edges, periodic ticks, blocking reads."""
from linux_time_high import main

if __name__ == '__main__':
    main('linux_timerfd_probe.c', 'TIMERFD_PASS:', 'linux-timerfd')
