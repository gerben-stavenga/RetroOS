#!/usr/bin/env python3
"""Exercise pthread startup and common syscall buffers on a high user stack."""
from linux_time_high import main

if __name__ == '__main__':
    main('linux_high_stack_probe.c', 'HIGH_STACK_PASS:', 'linux-high-stack')
