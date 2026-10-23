#!/usr/bin/env python3
"""Unchanged DOS Doom over native OSD IPX LAN or the COM1 null-modem cable."""
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
from lan_fixture import LanPair
ROOT = Path(__file__).resolve().parents[1]
def run(*args): subprocess.run(list(map(str,args)),cwd=ROOT,check=True,stdout=subprocess.DEVNULL)
def packets(path):
    data = path.read_bytes()
    offset = 24
    while offset + 16 <= len(data):
        length = struct.unpack_from('<I',data,offset+8)[0]
        offset += 16
        if offset + length > len(data): break
        yield data[offset:offset+length]
        offset += length

def traffic(pair,serial):
    counts = []
    for index,path in enumerate(pair.pcaps):
        count = 0
        for packet in packets(path):
            if len(packet)<54 or packet[6:12] != bytes.fromhex(f'5254001234{index+1:02x}') or packet[12:14]!=b'\x08\x00': continue
            ip = 14+(packet[14]&15)*4
            if serial:
                if packet[23]==6 and 1214 in struct.unpack_from('!HH',packet,ip):
                    count += struct.unpack_from('!H',packet,16)[0] > (ip-14)+((packet[ip+12]>>4)*4)
            elif packet[23]==17 and 213 in struct.unpack_from('!HH',packet,ip):
                payload = packet[ip+8:]
                if len(payload)>=42 and struct.unpack_from('<i',payload,30)[0]>=0: count+=1
        counts.append(count)
    return counts

def main():
    serial = '--serial' in sys.argv
    run('bazelisk','build','//:boot_disk')
    with tempfile.TemporaryDirectory(prefix='retroos-lan-doom-') as folder:
        work = Path(folder)
        data = work/'doom.img'
        with data.open('wb') as stream: stream.truncate(32*1024*1024)
        run('mkfs.fat','-F','16',data)
        games = ROOT/'showcase-bundle/GAMES/DOOMS'
        for name in ('DOOM.EXE','IPXSETUP.EXE','SERSETUP.EXE','DOOM1.WAD','DEFAULT.CFG'):
            run('mcopy','-i',data,games/name,'::/')
        command = ('SERSETUP.EXE -com1' + (' -8250' if '--8250' in sys.argv else '') if serial else 'IPXSETUP.EXE -nodes 2') + ' -deathmatch -warp 1 1 -nosound -nomouse -nojoy'
        pair = LanPair.__new__(LanPair)
        try:
            pair.__init__(work,data,[command]*2)
            pair.start(serial)
            pair.wait(lambda: all('ST_Init' in pair.text(i) for i in range(2)),90)
            assert all('of 2 (2 nodes)' in pair.text(i) for i in range(2)),pair.details()
            baseline = traffic(pair,serial)
            pair.wait(lambda: all(count-start >= 100 for count,start in zip(traffic(pair,serial),baseline)),30)
            assert all('!!! FATAL' not in pair.text(i) for i in range(2)),pair.details()
            print(f'PASS: Doom {"SERSETUP/COM1" if serial else "IPXSETUP"} via OSD LAN; packets {traffic(pair,serial)}')
        finally:
            pair.close()
if __name__=='__main__': main()
