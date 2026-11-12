#!/usr/bin/env python3
"""Verify pipe-to-null splice and its asynchronous completion semantics."""
from linux_time_high import main
if __name__ == '__main__':
    main('linux_splice_probe.c', 'SPLICE_PASS:', 'linux-splice')
