"""Build a tiny PE forwarder DLL with no import directory or executable code.

FORWARD.Entry resolves through RELAY.Entry to NTDLL.RtlCompareMemory.
Neither RELAY nor NTDLL is an ordinary dependency of the forwarder DLLs.
"""
import struct
import sys
from pathlib import Path

data = bytearray(0x400)
data[:2] = b"MZ"
struct.pack_into("<I", data, 0x3c, 0x80)
data[0x80:0x84] = b"PE\0\0"
struct.pack_into("<HHIIIHH", data, 0x84, 0x14c, 1, 0, 0, 0, 224, 0x2102)
opt = 0x98
struct.pack_into("<H", data, opt, 0x10b)
for offset, value in [(28, 0x18000000), (32, 4096), (36, 512), (56, 8192),
                       (60, 512), (92, 16), (96, 4096), (100, 512)]:
    struct.pack_into("<I", data, opt + offset, value)
struct.pack_into("<H", data, opt + 68, 3)
section = opt + 224
data[section:section + 8] = b".edata\0\0"
for offset, value in [(8, 512), (12, 4096), (16, 512), (20, 512), (36, 0x40000040)]:
    struct.pack_into("<I", data, section + offset, value)
for offset, value in [(16, 1), (20, 1), (24, 1), (28, 0x1040), (32, 0x1044), (36, 0x1048)]:
    struct.pack_into("<I", data, 512 + offset, value)
struct.pack_into("<IIH", data, 0x240, 0x1060, 0x1050, 0)
data[0x250:0x256] = b"Entry\0"
target = sys.argv[2].encode("ascii") + b"\0"
assert len(target) <= 0x1a0
data[0x260:0x260 + len(target)] = target
Path(sys.argv[1]).write_bytes(data)
