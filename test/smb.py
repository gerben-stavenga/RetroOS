#!/usr/bin/env python3
"""Authenticated signed SMB2 through the common VFS and QEMU VirtIO NIC.
Requires Samba's smbd and pdbedit (or SMB_TEST_SMBD / SMB_TEST_PDBEDIT).
All server state and exported files live in a private temporary directory.
"""
from pathlib import Path
import os
import pwd
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import threading
from boot_fixture import prepare_boot

ROOT=Path(__file__).resolve().parents[1]

def run(*args, **kwargs):
    return subprocess.run(list(map(str,args)), cwd=ROOT, check=True, stdout=subprocess.DEVNULL, **kwargs)

def vm(work, port, password='retrotest', uefi=False, entropy=True, fault=None):
    work.mkdir()
    data=work/'data.img'
    with data.open('wb') as stream:stream.truncate(32*1024*1024)
    run('mkfs.fat','-F','16',data);run('mmd','-i',data,'::RETROOS')
    flags=[] if password=='retrotest' and entropy else ['-DEXPECT_FAILURE']
    if fault: flags=['-DEXPECT_TAMPER' if fault=='tamper' else '-DEXPECT_IO_FAILURE']
    run('gcc','-m32','-nostdlib','-static','-no-pie','-fno-pic','-fno-stack-protector','-O2','-e','_start',*flags,ROOT/'test/smb_probe.c','-o',work/'SMB.ELF')
    run('mcopy','-i',data,work/'SMB.ELF','::SMB.ELF')
    username=pwd.getpwuid(os.getuid()).pw_name
    if not flags:
        run('nasm','-f','bin',ROOT/'test/smb_dos.asm','-o',work/'SMBDOS.COM')
        run('mcopy','-i',data,work/'SMBDOS.COM','::SMBDOS.COM')
    commands='SMB.ELF' if flags else 'SMB.ELF;SMBDOS.COM'
    config=f'[environment]\nTEST={commands}\n[smb]\nserver=10.0.2.2\nport={port}\nshare=share\nusername={username}\npassword={password}\npath=/home/retroos/NET\n'
    config+=f'[smb]\nserver=10.0.2.2\nport={port}\nshare=readonly\nusername={username}\npassword={password}\npath=/RO\n'
    config+=f'[smb]\nserver=10.0.2.2\nport={port}\nshare=share\nusername={username}\npassword={password}\npath=/host\ndrive=H\n'
    boot=prepare_boot(work,data,config)
    log=work/'klog'
    args=['qemu-system-x86_64','-cpu','max' if entropy else 'max,-rdrand','-m','256','-display','none','-serial','none','-no-reboot','-debugcon',f'file:{log}','-drive',f'file={boot},format=raw,snapshot=on','-drive',f'file={data},format=raw,snapshot=on','-nic','none','-netdev','user,id=net0','-device',('virtio-net-pci,disable-legacy=on' if uefi else 'virtio-net-pci')+',netdev=net0']
    if uefi:
        shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd',work/'vars.fd')
        args+=['-drive','if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd','-drive',f'if=pflash,format=raw,file={work/"vars.fd"}']
    with (work/'stderr').open('w') as errors:
        process=subprocess.Popen(args,cwd=ROOT,stdout=subprocess.DEVNULL,stderr=errors)
        try:
            deadline=time.monotonic()+60
            while time.monotonic()<deadline:
                text=log.read_text(errors='replace') if log.exists() else ''
                exits=re.findall(r'\[mem\] exit tid=\d+ code=(-?\d+) ',text)
                if len(exits)>=(1 if flags else 2) or 'PANIC' in text or 'FATAL' in text:break
                assert process.poll() is None, (text,(work/'stderr').read_text())
                time.sleep(.1)
            assert exits==(['0'] if flags else ['0','0']),text[-10000:]
            if password!='retrotest' or not entropy:
                assert 'SMB: mount /home/retroos/NET failed' in text,text[-5000:]
            else:
                assert 'SMB: mounted /home/retroos/NET (authenticated, signed SMB2)' in text,text[-5000:]
            assert password not in text, 'password leaked to log'
        finally:
            process.terminate();process.wait(timeout=5)
    print('PASS:',work.name,flush=True)

class Proxy:
    """Frame-aware fault injection; never logs credentials or packet contents."""
    def __init__(self, upstream, fault):
        self.upstream=upstream;self.fault=fault;self.stop=threading.Event();self.sockets=[]
        self.listener=socket.socket();self.listener.bind(('127.0.0.1',0));self.listener.listen();self.listener.settimeout(.2)
        self.port=self.listener.getsockname()[1]
        self.thread=threading.Thread(target=self.accept,daemon=True);self.thread.start()
    def accept(self):
        while not self.stop.is_set():
            try:client,_=self.listener.accept()
            except (TimeoutError,OSError):continue
            server=socket.create_connection(('127.0.0.1',self.upstream),timeout=5)
            self.sockets.extend([client,server])
            for source,target,reply in [(client,server,False),(server,client,True)]:
                threading.Thread(target=self.pump,args=(source,target,reply),daemon=True).start()
    @staticmethod
    def exact(stream,count):
        data=bytearray()
        while len(data)<count:
            chunk=stream.recv(count-len(data))
            if not chunk:raise EOFError()
            data.extend(chunk)
        return data
    def pump(self,source,target,reply):
        try:
            while not self.stop.is_set():
                prefix=self.exact(source,4);count=int.from_bytes(prefix,'big')
                assert 64<=count<=66048
                data=self.exact(source,count);command=int.from_bytes(data[12:14],'little')
                if self.fault=='stall' and not reply and command==5:
                    self.stop.wait(10);return
                if self.fault=='tamper' and reply and command==8 and int.from_bytes(data[8:12],'little')==0:
                    data[-1]^=1
                target.sendall(prefix+data)
        except (OSError,EOFError):pass
    def close(self):
        self.stop.set();self.listener.close()
        for stream in self.sockets:
            try:stream.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            stream.close()
        self.thread.join(timeout=2)

def main():
    smbd=os.environ.get('SMB_TEST_SMBD') or shutil.which('smbd')
    pdbedit=os.environ.get('SMB_TEST_PDBEDIT') or shutil.which('pdbedit')
    if not smbd or not pdbedit:
        print('SKIP: Samba smbd and pdbedit required');return
    run('bazelisk','build','//:boot_disk')
    work=Path(tempfile.mkdtemp(prefix='retroos-smb-'));print('Artifacts:',work,flush=True)
    for directory in ['private','lock','cache','state','run','share']:(work/directory).mkdir()
    (work/'share/seed.txt').write_bytes(b'SMB seed!\n')
    listing=work/'share/listing';listing.mkdir()
    for i in range(600):(listing/f'f{i:04}.txt').write_bytes(b'entry')
    username=pwd.getpwuid(os.getuid()).pw_name
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0));port=listener.getsockname()[1]
    config=work/'smb.conf'
    config.write_text(f'''[global]
server role = standalone server
security = user
workgroup = WORKGROUP
netbios name = RETROTEST
interfaces = 127.0.0.1
bind interfaces only = yes
smb ports = {port}
server min protocol = SMB2_02
server max protocol = SMB2_10
server signing = mandatory
passdb backend = tdbsam:{work}/private/passdb.tdb
private dir = {work}/private
lock directory = {work}/lock
cache directory = {work}/cache
state directory = {work}/state
pid directory = {work}/run
ncalrpc dir = {work}/run/ncalrpc
winbindd socket directory = {work}/run/winbindd
log file = {work}/samba.log
logging = file
load printers = no
printing = bsd
printcap name = /dev/null
[share]
path = {work}/share
read only = no
valid users = {username}
[readonly]
path = {work}/share
read only = yes
valid users = {username}
''')
    config.chmod(0o600)
    run(pdbedit,'-t','-a','-u',username,'-s',config,input=b'retrotest\nretrotest\n')
    # Distribution Samba services require root; opt in on disposable CI runners.
    service_prefix = ["sudo", "-n"] if os.environ.get("SMB_TEST_SUDO") == "1" else []
    # Foreground smbd exits on stdin EOF; CI itself has no open input.
    with (work/'samba-stderr').open('w') as errors:
        server=subprocess.Popen(service_prefix + [smbd,'-F','--no-process-group','--debug-stdout','-s',str(config)],stdin=subprocess.PIPE,stdout=errors,stderr=errors,start_new_session=True)
        try:
            deadline=time.monotonic()+5
            while True:
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.2):break
                except OSError:
                    assert server.poll() is None, (work/'samba-stderr').read_text() + ((work/'samba.log').read_text() if (work/'samba.log').exists() else '')
                    assert time.monotonic()<deadline,'Samba did not start'
                    time.sleep(.05)
            for name,options in [('bios',{}),('uefi',{'uefi':True}),('bad-password',{'password':'wrong-password'}),('no-entropy',{'entropy':False})]:
                vm(work/name,port,**options)
                if not options or options.get('uefi'):
                    assert (work/'share/verified.txt').read_bytes()==b'RetroOS SMB PASS\n'
                    assert (work/'share/DOS.TXT').read_bytes()==b'DOS through shared SMB VFS\r\n'
                    assert not (work/'share/work').exists()
                    assert not (work/'share/forbidden.txt').exists()
            for fault in ['stall','tamper']:
                proxy=Proxy(port,fault)
                try:vm(work/fault,proxy.port,fault=fault)
                finally:proxy.close()
        finally:
            if server.poll() is None:
                if service_prefix:
                    subprocess.run(service_prefix + ['kill', '-TERM', '--', '-' + str(server.pid)], check=False)
                else:
                    os.killpg(server.pid,signal.SIGTERM)
            server.wait(timeout=5)

if __name__=='__main__':main()
