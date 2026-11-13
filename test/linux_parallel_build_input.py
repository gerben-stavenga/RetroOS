#!/usr/bin/env python3
"""Build NASM with eight GCC jobs while typing through an xHCI USB keyboard."""
import json, os, shutil, socket, subprocess, tempfile, time
from pathlib import Path
from boot_fixture import ROOT, prepare_boot

def compiler_summary(path):
    active={};peak=0;cpus=set();peak_cpus=set();distinct_peak=set();invocations=0
    for line in path.read_text().splitlines():
        kind,pid,cpu,apic,ns,status,instance=line.split();pid=int(pid);cpu=int(cpu);instance=int(instance)
        if kind=='START':
            assert cpu==int(apic), 'getcpu disagrees with physical CPUID in this VM'
            assert instance not in active
            active[instance]=(pid,cpu);cpus.add(cpu);invocations+=1
        else:
            assert int(status)==0 and active[instance][0]==pid;active.pop(instance)
        running={cpu for pid,cpu in active.values()}
        if len(active)>peak:peak=len(active);peak_cpus=running
        if len(running)>len(distinct_peak):distinct_peak=running
    assert not active,active
    return {'compiler_invocations':invocations,'peak_overlapping_compilers':peak,
            'all_cpus':sorted(cpus),'cpus_at_first_peak':sorted(peak_cpus),
            'peak_distinct_compiler_cpus':len(distinct_peak),'distinct_peak_cpus':sorted(distinct_peak)}


def main():
    artifacts=ROOT/'build/ci/parallel-build-input'; artifacts.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='retroos-compile-input-') as directory:
        work=Path(directory); tree=work/'root'
        subprocess.run(['cp','-a','--reflink=auto',str(ROOT/'build/ci/cache-invalidation-build/native-root'),str(tree)],check=True)
        project=tree/'project'; project.mkdir()
        # Repositories need not be linked into the current target's execroot.
        output_base=(ROOT/'bazel-RetroOS').resolve().parent.parent
        external=output_base/'external/nasm~'
        shutil.copytree(external,project/'nasm',symlinks=False)
        shutil.copyfile(external/'config_linux.h',project/'nasm/config/config.h')
        for name,flags in [('probe',[]),('ccwrap',['-DCOMPILER_WRAPPER'])]:
            subprocess.run(['gcc','-O2','-static',*flags,str(ROOT/'test/linux_parallel_build_probe.c'),'-o',str(project/name)],check=True)
        # The fixture already has gcc/cc1/as/ld; ar is needed for NASM's library.
        shutil.copy2('/usr/bin/ar',tree/'usr/bin/ar')
        sources=sorted(str(p.relative_to(project)) for p in (project/'nasm').rglob('*.c')
            if p.parent.name in ['asm','common','disasm','macros','nasmlib','output','stdlib','x86'] and p.name!='nasm.c')
        objects=[p[:-2]+'.o' for p in sources]
        (project/'Makefile').write_text('CC=/usr/bin/gcc\nCFLAGS=-O2 -w -DHAVE_CONFIG_H -Inasm -Inasm/include -Inasm/x86 -Inasm/asm -Inasm/disasm -Inasm/output -wrapper /project/ccwrap\nOBJECTS='+' '.join(objects)+'\nall: libnasm.a\nlibnasm.a: $(OBJECTS)\n\t/usr/bin/ar rcs $@ $^\n')
        image=work/'root.ext4'
        with image.open('wb') as out: out.truncate(2*1024**3)
        subprocess.run(['mkfs.ext4','-q','-F','-d',str(tree),str(image)],check=True)
        boot=prepare_boot(work,image,'[environment]\nTEST=/project/probe\n')
        qmp=work/'qmp.sock'; log=artifacts/'klog.txt'
        with log.open('w') as out:
            vm=subprocess.Popen(['qemu-system-x86_64','-accel','kvm','-cpu','host','-machine','q35,i8042=off','-smp','16','-m','4096',
                '-device','qemu-xhci,id=xhci','-device','usb-kbd,bus=xhci.0','-display','none','-serial','none','-monitor','none','-nic','none','-no-reboot','-debugcon','stdio',
                '-gdb',f'unix:{work}/gdb.sock,server=on,wait=off','-qmp',f'unix:{qmp},server=on,wait=off','-drive',f'file={boot},format=raw,snapshot=on','-drive',f'file={image},format=raw,if=none,id=data','-device','nvme,drive=data,serial=COMPILE'],stdout=out,stderr=subprocess.STDOUT)
            connection=None
            try:
                deadline=time.monotonic()+30
                while not qmp.exists():
                    assert vm.poll() is None and time.monotonic()<deadline; time.sleep(.1)
                connection=socket.socket(socket.AF_UNIX); connection.connect(str(qmp)); connection.settimeout(3)
                stream=connection.makefile('rwb'); stream.readline()
                def command(name,**arguments):
                    stream.write((json.dumps({'execute':name,'arguments':arguments})+'\n').encode()); stream.flush()
                    while True:
                        line=stream.readline()
                        if not line: raise EOFError('QEMU closed its control socket')
                        reply=json.loads(line); assert 'error' not in reply,reply
                        if 'return' in reply:return reply['return']
                command('qmp_capabilities')
                deadline=time.monotonic()+35
                while 'event_loop entered' not in log.read_text():
                    assert vm.poll() is None and time.monotonic()<deadline;time.sleep(.2)
                # USB HID down/up transitions exercise both transfer and event ring wraps.
                for i in range(1200):
                    if i % 25 == 0:
                        current_log=log.read_text(errors='replace')
                        assert '!!! KERNEL PANIC !!!' not in current_log, current_log[-3000:]
                    if vm.poll() is not None: break
                    try:
                        command('input-send-event',events=[{'type':'key','data':{'down':True,'key':{'type':'qcode','data':'a'}}}])
                        time.sleep(.02)
                        command('input-send-event',events=[{'type':'key','data':{'down':False,'key':{'type':'qcode','data':'a'}}}])
                        time.sleep(.02)
                    except (OSError,EOFError):
                        # The probe exits on the thousandth key-down; shutdown
                        # can close QMP before the corresponding key-up.
                        vm.wait(timeout=5)
                        break
                vm.wait(timeout=180)
            finally:
                if connection and vm.poll() is None:
                    try:
                        snapshots=[]
                        for cpu in range(16):
                            command('human-monitor-command', **{'command-line':f'cpu {cpu}'})
                            snapshots.append(command('human-monitor-command', **{'command-line':'info registers'}))
                        (artifacts/'registers.txt').write_text('\n'.join(snapshots))
                    except (OSError,AssertionError):pass
                if connection:connection.close()
                if vm.poll() is None:vm.terminate();vm.wait(timeout=5)
                for name in ['state','build.log','compilers.log','libnasm.a']:
                    subprocess.run(['debugfs','-R',f'dump /project/{name} {artifacts/name}',str(image)],capture_output=True,check=True)
        text=log.read_text();assert vm.returncode==0 and 'PARALLEL_BUILD_INPUT_PASS' in text,text[-5000:]
        result=compiler_summary(artifacts/'compilers.log')
        (artifacts/'result.json').write_text(json.dumps(result,indent=2)+'\n')
        assert result['peak_overlapping_compilers']>=4 and result['peak_distinct_compiler_cpus']>=4,result
        print(json.dumps(result),flush=True)
        print('PASS: real NASM C compilation with USB typing and distinct compiler CPUs',flush=True)
if __name__=='__main__':main()
