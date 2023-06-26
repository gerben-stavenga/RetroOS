#!/usr/bin/python3

import sys
import io

file = io.open(sys.argv[1],mode="rb")
all_of_it = file.read()
file.close()
l = len(all_of_it)
nl = (l + 511) & ~511
all_of_it = all_of_it.ljust(nl, b'\x00')

sys.stdout.buffer.write(all_of_it)

