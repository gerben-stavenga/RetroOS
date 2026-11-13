#!/usr/bin/env python3
"""Verify inode-based descriptor metadata across writes and namespace changes."""
import os
import tempfile
from linux_time_high import main
if __name__ == '__main__':
    with tempfile.TemporaryDirectory(prefix='retroos-fd-metadata-host-') as directory:
        os.environ['FD_METADATA_ROOT'] = directory
        main('linux_fd_metadata_probe.c', 'FD_METADATA_PASS:', 'linux-fd-metadata', extra_binaries=('/usr/bin/cp','/bin/bash','/bin/sh','/bin/tar'))
