#!/usr/bin/env python3
"""Verify heap growth failures preserve the program break and live pages."""
from linux_time_high import main

if __name__ == '__main__':
    main('linux_brk_probe.c', 'BRK_PASS:', 'linux-brk')
