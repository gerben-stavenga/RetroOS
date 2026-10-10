#!/usr/bin/env python3
"""Repeat RC in a private 128 MiB BIOS VM to check ELF load memory use."""
import json, socket, subprocess, time, tempfile, re
from pathlib import Path
from boot_fixture import prepare_boot

root=Path(__file__).resolve().parents[1]
subprocess.run(['bazelisk', 'build', '//:boot_disk'], cwd=root, check=True)
work=Path(tempfile.mkdtemp(prefix='retroos-rc-repeat-'))
print(work,flush=True)
disk=work/'data.img'; disk.write_bytes(b''); disk.open('r+b').truncate(32*1024*1024)
def run(*a): subprocess.run(list(map(str,a)),check=True,stdout=subprocess.DEVNULL)
run('mkfs.fat','-F','16',disk)
run('mmd','-i',disk,'::RETROOS')
config=(root/'etc/RETROOS.INI').read_bytes()
(work/'RETROOS.INI').write_bytes(config)
run('mcopy','-i',disk,work/'RETROOS.INI','::RETROOS/RETROOS.INI')
boot=prepare_boot(work,disk)
log=work/'boot.log'; sock=work/'qmp'
p=subprocess.Popen(['qemu-system-x86_64','-accel','kvm','-cpu','host','-m','128','-display','none','-serial','none','-drive',f'file={boot},format=raw,snapshot=on','-drive',f'file={disk},format=raw,snapshot=on','-device',f'VGA,romfile={root}/third_party/vgabios/vgabios-stdvga.bin','-audiodev','none,id=snd0','-device','intel-hda','-device','hda-duplex,audiodev=snd0','-debugcon',f'file:{log}','-qmp',f'unix:{sock},server=on,wait=off','-no-reboot'],stdout=subprocess.DEVNULL,stderr=(work/'stderr').open('w'))
def text(): return log.read_text(errors='replace') if log.exists() else ''
def wait(pred,timeout=40):
 end=time.monotonic()+timeout
 while time.monotonic()<end:
  t=text()
  assert not any(s in t for s in ['KERNEL PANIC','SEGV']),t[-4000:]
  if pred(t): return t
  assert p.poll() is None,t[-4000:]
  time.sleep(.1)
 raise AssertionError(text()[-4000:])
try:
 wait(lambda t:'Dos Navigator  Version 1.51' in t)
 c=socket.socket(socket.AF_UNIX); c.connect(str(sock)); c.settimeout(5)
 s=c.makefile('rwb'); s.readline()
 def call(cmd,**args):
  s.write((json.dumps(dict(execute=cmd,arguments=args))+'\n').encode());s.flush()
  while True:
   out=json.loads(s.readline())
   assert 'error' not in out,out
   if 'return' in out:return out['return']
 call('qmp_capabilities')
 def key(k): call('human-monitor-command',**{'command-line':'sendkey '+k});time.sleep(.08)
 keys={':':'shift-semicolon','\\':'backslash','.':'dot',' ':'spc'}
 time.sleep(2)
 for cycle in range(8):
  for ch in 'c:\\rc\\rc.exe':key(keys.get(ch,ch))
  key('ret')
  wait(lambda t:t.count('parent tid=1 continues without blocking')>=cycle+1)
  time.sleep(5)
  call('screendump',filename=str(work/f'rc-{cycle}.ppm'))
  key('f10');time.sleep(.6);key('ret')
  t=wait(lambda t:len(re.findall(r'\[mem\] exit tid=\d+ code=0',t))>=cycle+1)
  loads = re.findall(r'handle_fork_exec:.*format=elf free_pages=(\d+)', t)
  assert int(loads[-1]) > 18000, 'ELF file payload retained during fork: ' + loads[-1]
  print('cycle',cycle+1,re.findall(r'handle_fork_exec:.*free_pages=\d+|\[mem\] exit.*',t)[-2:],flush=True)
  time.sleep(2)
 print('PASS: eight RC launch/quit cycles, BIOS 128 MiB, streamed ELF headroom', flush=True)
 call('quit')
finally:
 if p.poll() is None:p.terminate()
 p.wait(timeout=5)
