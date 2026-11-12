#!/usr/bin/env python3
"""Exercise static/dynamic libc vDSO lookup and verify eliminated syscalls."""
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
from boot_fixture import ROOT, prepare_boot
sys.path.insert(0, str(ROOT/'tools'))
from importlib.machinery import SourceFileLoader
bridge=SourceFileLoader('vdso_bridge',str(ROOT/'tools/86box_mcp.py')).load_module()


def run_case(kind):
    with tempfile.TemporaryDirectory(prefix='retroos-vdso-') as directory:
        work=Path(directory); tree=work/'root'
        (tree/'home/retroos/RETROOS').mkdir(parents=True)
        probe=tree/'probe'
        subprocess.run(['gcc','-O2',*(['-static'] if kind!='dynamic' else []),
                        str(ROOT/'test/linux_vdso_probe.c'),'-o',str(probe)],check=True)
        if kind=='dynamic':
            dependencies=subprocess.check_output(['ldd',str(probe)],text=True)
            for name in re.findall(r'(/\S+)',dependencies):
                target=tree/name.lstrip('/'); target.parent.mkdir(parents=True,exist_ok=True)
                shutil.copyfile(name,target)
        image=work/'data.ext4'
        with image.open('wb') as output: output.truncate(32*1024*1024)
        subprocess.run(['mkfs.ext4','-q','-F','-d',str(tree),str(image)],check=True)
        fallback=kind=='fallback'
        boot=prepare_boot(work,image,'[environment]\nTEST=/probe'+(' --fallback' if fallback else '')+'\n')
        log=ROOT/'build/ci'/f'linux-vdso-{kind}.log'
        endpoint=work/'mcp.sock'
        with log.open('w') as output:
            vm=subprocess.Popen(['qemu-system-x86_64','-accel','kvm','-cpu',
                'host,-invtsc,-hypervisor' if fallback else 'host','-m','512','-display','none',
                '-serial','none','-chardev',f'socket,id=mcp,path={endpoint},server=on,wait=off',
                '-serial','chardev:mcp','-fw_cfg','name=opt/mcp,string=com2','-no-reboot','-nic','none',
                '-debugcon','stdio','-drive',f'file={boot},format=raw,snapshot=on',
                '-drive',f'file={image},format=raw,snapshot=on'],stdout=output,stderr=subprocess.STDOUT)
            control=None
            try:
                deadline=time.monotonic()+60
                def await_log(marker):
                    while marker not in log.read_text():
                        if vm.poll() is not None or time.monotonic()>deadline:
                            raise AssertionError(log.read_text()[-3000:])
                        time.sleep(.005)
                await_log('event_loop entered')
                control=bridge.SerialControl(None,str(endpoint))
                control.request('profile reset'); control.request('profile on')
                await_log('VDSO_FALLBACK_PASS:' if fallback else 'VDSO_PASS:')
                control.request('profile off')
                report=control.request('profile syscalls')
                (ROOT/'build/ci'/f'linux-vdso-{kind}.json').write_text(json.dumps(report,indent=2))
                clocks=next(c['calls'] for c in report['syscalls'] if c['abi']==64 and c['nr']==228)
                if fallback: assert clocks>=2, report
                else: assert clocks==14, ('libc/direct fast reads must not syscall',clocks,report)
                control.request('profile reset')
                assert control.request('profile syscalls')['syscalls']==[]
                vm.wait(timeout=10)
                assert vm.returncode==0 and '[mem] exit tid=1 code=0' in log.read_text(),log.read_text()[-3000:]
            finally:
                if control: control.close()
                if vm.poll() is None: vm.terminate();vm.wait(timeout=5)
        print('PASS:',kind,'clock syscalls:',clocks,flush=True)


if __name__=='__main__':
    (ROOT/'build/ci').mkdir(parents=True,exist_ok=True)
    for case in ('static','dynamic','fallback'): run_case(case)
