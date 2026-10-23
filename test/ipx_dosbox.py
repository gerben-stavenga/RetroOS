#!/usr/bin/env python3
"""Original Doom between RetroOS/QEMU and DOSBox, in both relay directions.

DOSBOX_BIN selects a DOSBox 0.74-compatible executable. Uses private game
copies and a loopback-only QEMU UDP forward; no public services are contacted.
Artifacts (logs, packet capture, RetroOS screenshot) are retained on failure.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import time

from boot_config import qemu
from boot_fixture import prepare_boot
from ipx_doom import packets
from lan_fixture import LanPair

ROOT = Path(__file__).resolve().parents[1]
COMMAND = 'IPXSETUP.EXE -nodes 2 -deathmatch -warp 1 1 -nosound -nomouse -nojoy'


def run(*args):
    subprocess.run(list(map(str, args)), cwd=ROOT, check=True, stdout=subprocess.DEVNULL)


def tic_times(path):
    """IPXSETUP's leading signed time is -1 during discovery, >=0 in game."""
    result = [set(), set()]
    if not path.exists():
        return result
    for packet in packets(path):
        if len(packet) < 42 or packet[12:14] != b'\x08\x00' or packet[23] != 17:
            continue
        udp = 14 + (packet[14] & 15) * 4
        if len(packet) < udp + 8 + 34:
            continue
        ipx = packet[udp + 8:]
        if ipx[:2] != b'\xff\xff' or ipx[16:18] != b'\x86\x9b':
            continue
        tic = struct.unpack_from('<i', ipx, 30)[0]
        if tic >= 0:
            result[packet[26:30] != bytes([10, 0, 2, 15])].add(tic)
    return result


class DoomSession(LanPair):
    def __init__(self, work, dosbox, dosbox_server):
        self.work = work
        self.processes, self.streams, self.controls = [], [], []
        self.logs = [work/'player0'/'guest.log']
        self.pcaps = [work/'traffic.pcap']
        player = work/'player0'
        player.mkdir()
        games = work/'dosbox'
        games.mkdir()
        data = work/'doom.img'
        with data.open('wb') as stream:
            stream.truncate(32 * 1024 * 1024)
        run('mkfs.fat', '-F', '16', data)
        for name in ('DOOM.EXE', 'IPXSETUP.EXE', 'DOOM1.WAD', 'DEFAULT.CFG'):
            source = ROOT/'showcase-bundle/GAMES/DOOMS'/name
            shutil.copyfile(source, games/name)
            run('mcopy', '-i', data, source, '::/')
        batch = work/'START.BAT'
        batch.write_text('@ECHO OFF\r\nECHO LAN-READY\r\nPAUSE\r\n'+COMMAND+'\r\n')
        run('mcopy', '-i', data, batch, '::START.BAT')
        run('mcopy', '-i', data, ROOT/'bazel-bin/tools/command/COMMAND.COM', '::COMMAND.COM')
        boot = prepare_boot(player, data, '[environment]\nTEST=COMMAND.COM /B START.BAT\n')
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        net = 'user,id=net0'
        if not dosbox_server:
            net += f',hostfwd=udp:127.0.0.1:{port}-:213'
        errors = (player/'qemu.stderr').open('w')
        self.streams.append(errors)
        args = qemu(self.logs[0]) + [
            '-drive', f'file={boot},format=raw,snapshot=on',
            '-drive', f'file={data},format=raw,snapshot=on',
            '-qmp', f'unix:{player}/qmp,server=on,wait=off',
            '-netdev', net, '-device', 'virtio-net-pci,netdev=net0',
            '-object', f'filter-dump,id=trace,netdev=net0,file={self.pcaps[0]}']
        self.processes.append(subprocess.Popen(args, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=errors))
        self.wait(lambda: 'LAN-READY' in self.text(0) and 'Network: DHCP IPv4' in self.text(0), 60)
        conn = socket.socket(socket.AF_UNIX)
        conn.connect(str(player/'qmp'))
        stream = conn.makefile('rwb')
        stream.readline()
        self.controls.append((conn, stream))
        self.call(0, 'qmp_capabilities')
        self.keys(0, ['f12'] + ['tab']*4)
        if not dosbox_server:
            self.keys(0, ['down', 'ret'])
            self.wait(lambda: 'IPXNET: hosting' in self.text(0), 5)
        config = work/'dosbox.conf'
        config.write_text(f'''[sdl]
fullscreen=false
output=surface
[dosbox]
memsize=16
[cpu]
core=normal
cycles=fixed 20000
[mixer]
nosound=true
[midi]
mpu401=none
[sblaster]
sbtype=none
[ipx]
ipx=true
[autoexec]
mount c "{games}"
c:
ipxnet {'startserver' if dosbox_server else 'connect 127.0.0.1'} {port} > CONNECT.TXT
{COMMAND} > DOOM.LOG
exit
''')
        output = (work/'dosbox.log').open('w')
        self.streams.append(output)
        env = dict(os.environ, SDL_VIDEODRIVER='dummy', SDL_AUDIODRIVER='dummy')
        self.processes.append(subprocess.Popen([dosbox, '-conf', str(config)], cwd=games, env=env, stdout=output, stderr=subprocess.STDOUT))
        if dosbox_server:
            # DOSBox's console output is redirected to a private DOS file.
            self.wait(lambda: (games/'CONNECT.TXT').exists() and 'started' in (games/'CONNECT.TXT').read_text(errors='replace'), 10)
            self.keys(0, ['down']*4 + ['ret'])
            address = f'10.0.2.2:{port}'
            self.keys(0, [{'0':'0', '.':'dot', ':':'semicolon'}.get(c,c) for c in address] + ['ret'])
            self.wait(lambda: 'IPXNET: connected' in self.text(0), 10)
        else:
            self.wait(lambda: 'IPXNET: client' in self.text(0), 10)
        self.keys(0, ['esc', 'ret'])

    def details(self):
        text = super().details()
        for name in ('dosbox.log', 'dosbox/CONNECT.TXT', 'dosbox/DOOM.LOG'):
            path = self.work/name
            if path.exists():
                text += '\n'+name+':\n'+path.read_text(errors='replace')[-5000:]
        return text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dosbox-server', action='store_true')
    args = parser.parse_args()
    binary = os.environ.get('DOSBOX_BIN') or shutil.which('dosbox')
    if not binary:
        parser.error('Install DOSBox or set DOSBOX_BIN to its executable')
    run('bazelisk', 'build', '//:boot_disk')
    work = Path(tempfile.mkdtemp(prefix='retroos-dosbox-doom-'))
    print('Artifacts:', work, flush=True)
    session = DoomSession.__new__(DoomSession)
    try:
        session.__init__(work, binary, args.dosbox_server)
        session.wait(lambda: 'ST_Init' in session.text(0), 90)
        assert 'of 2 (2 nodes)' in session.text(0), session.details()
        baseline = [len(t) for t in tic_times(session.pcaps[0])]
        # Distinct advancing tic numbers in both directions prove gameplay,
        # not just repeated setup packets or a stalled game's retransmissions.
        session.wait(lambda: all(len(t)-n >= 100 for t,n in zip(tic_times(session.pcaps[0]), baseline)), 45)
        session.call(0, 'screendump', filename=str(work/'retroos.ppm'))
        print(f'PASS: original Doom RetroOS/QEMU <-> DOSBox; relay={"DOSBox" if args.dosbox_server else "RetroOS"}; distinct tics={[len(t) for t in tic_times(session.pcaps[0])]}', flush=True)
    finally:
        session.close()


if __name__ == '__main__':
    main()
