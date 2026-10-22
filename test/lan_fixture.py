"""Two RetroOS VMs on one Ethernet segment; use the real OSD to join a LAN."""
import json
from pathlib import Path
import socket
import subprocess
import time
from boot_config import qemu
from boot_fixture import prepare_boot

ROOT = Path(__file__).resolve().parents[1]

class LanPair:
    def __init__(self, work, data, commands):
        self.work = work
        self.processes = []
        self.streams = []
        self.logs = []
        self.controls = []
        self.pcaps = []
        # QEMU multicast joins the two virtual hubs. Only the first supplies
        # DHCP/NAT; both guests therefore have distinct addresses on one LAN.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as port:
            port.bind(('127.0.0.1', 0))
            multicast_port = port.getsockname()[1]
        for index, command in enumerate(commands):
            player = work / f'player{index}'
            player.mkdir()
            batch = player/'START.BAT'
            batch.write_text('@ECHO OFF\r\nECHO LAN-READY\r\nPAUSE\r\n'+command+'\r\n')
            # Each gets its own data image so different test scripts stay private.
            import shutil
            private = player/'data.img'
            shutil.copyfile(data, private)
            subprocess.run(['mcopy','-o','-i',str(private),str(batch),'::START.BAT'],check=True)
            subprocess.run(['mcopy','-o','-i',str(private),str(ROOT/'bazel-bin/tools/command/COMMAND.COM'),'::COMMAND.COM'],check=True)
            disk = prepare_boot(player, private, '[environment]\nTEST=COMMAND.COM /B START.BAT\n')
            log = player/'guest.log'
            self.logs.append(log)
            qmp = player/'qmp'
            pcap = player/'traffic.pcap'
            self.pcaps.append(pcap)
            errors = (player/'qemu.stderr').open('w')
            self.streams.append(errors)
            args = qemu(log) + ['-drive',f'file={disk},format=raw,snapshot=on',
                '-drive',f'file={private},format=raw,snapshot=on',
                '-qmp',f'unix:{qmp},server=on,wait=off',
                '-netdev',f'socket,id=link,mcast=230.42.13.1:{multicast_port}',
                '-netdev','hubport,id=linkport,hubid=0,netdev=link',
                '-netdev','hubport,id=nicport,hubid=0',
                '-device',f'virtio-net-pci,netdev=nicport,mac=52:54:00:12:34:{index+1:02x}',
                '-object',f'filter-dump,id=trace,netdev=link,file={pcap}']
            if index == 0: args += ['-netdev','user,id=wan','-netdev','hubport,id=wanport,hubid=0,netdev=wan']
            self.processes.append(subprocess.Popen(args,cwd=ROOT,stdout=subprocess.DEVNULL,stderr=errors))
        self.wait(lambda: all('LAN-READY' in self.text(i) for i in range(2)), 60)
        for index in range(2):
            conn = socket.socket(socket.AF_UNIX)
            conn.connect(str(work/f'player{index}'/'qmp'))
            stream = conn.makefile('rwb')
            stream.readline()
            self.controls.append((conn,stream))
            self.call(index,'qmp_capabilities')
        # Let DHCP finish before creating the room.
        self.wait(lambda: all('Network: DHCP IPv4' in self.text(i) for i in range(2)), 30)
        # Slirp resets unsolicited TCP packets on a shared hub, including a
        # second guest's replies. Remove its port after supplying the leases.
        self.call(0,'netdev_del',id='wan')
        self.keys(0, ['f12'] + ['tab']*4 + ['down','ret'])
        self.wait(lambda: 'LAN: selected ' in self.text(0), 5)
        self.keys(1, ['f12'] + ['tab']*4)
        time.sleep(2)
        self.keys(1, ['down']*4 + ['ret'])
        self.wait(lambda: 'LAN: selected ' in self.text(1), 5)
        room = self.text(0).split('LAN: selected ')[-1].splitlines()[0]
        assert room != '0000000000000000' and ('LAN: selected '+room) in self.text(1), self.details()
        time.sleep(2)
    def text(self,index):
        path = self.logs[index]
        return path.read_text(errors='replace') if path.exists() else ''
    def details(self):
        return '\n'.join(self.text(i)[-5000:] + '\n'+(self.work/f'player{i}'/'qemu.stderr').read_text() for i in range(len(self.logs)))
    def wait(self,predicate,timeout):
        deadline = time.monotonic()+timeout
        while time.monotonic()<deadline:
            if predicate(): return
            if any(p.poll() is not None for p in self.processes) or any('!!! FATAL' in self.text(i) for i in range(len(self.logs))): break
            time.sleep(.1)
        raise AssertionError(self.details())
    def call(self,index,command,**arguments):
        stream = self.controls[index][1]
        stream.write((json.dumps(dict(execute=command,arguments=arguments))+'\n').encode())
        stream.flush()
        while True:
            response = json.loads(stream.readline())
            assert 'error' not in response,response
            if 'return' in response: return response['return']
    def keys(self,index,keys):
        for key in keys:
            self.call(index,'send-key',keys=[{'type':'qcode','data':key}],**{'hold-time':50})
            time.sleep(.5 if key=='f12' else .2)
    def start(self,serial=False):
        if serial:
            # Creator selection is row 1; joiner's selection resets to row 3
            # when its joined room disappears from the list.
            self.keys(0,['down','down','ret'])
            self.keys(1,['ret'])
            self.wait(lambda: 'LAN: null-modem connected' in self.text(0),10)
        for index in range(2): self.keys(index,['esc'])
        for index in (1,0): self.keys(index,['ret'])
    def close(self):
        for process in self.processes:
            if process.poll() is None: process.terminate()
            process.wait(timeout=5)
        for _,stream in self.controls: stream.close()
        for conn,_ in self.controls: conn.close()
        for stream in self.streams: stream.close()
