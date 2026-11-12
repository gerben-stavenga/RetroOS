#!/usr/bin/env python3
"""Compare real native builds across kernels with a frozen ext4 tool/input image."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
from boot_fixture import ROOT, prepare_boot
import native_program_profile

BENCHMARK = r'''
import json, os, subprocess, time
from pathlib import Path
work=Path('/home/retroos/project'); work.mkdir(exist_ok=True)
for unit in range(8):
    (work/f'unit{unit}.c').write_text('#include <stdint.h>\n'+'\n'.join('uint64_t f%d_%d(uint64_t x) { for (unsigned j=0;j<32;j++) x=(x*%du)^(x>>13); return x; }'%(unit,i,2*i+3) for i in range(100))+'\n')
(work/'main.c').write_text('#include <stdio.h>\nint main(void) { puts("PROJECT_BUILD_PASS"); return 0; }\n')
(work/'Makefile').write_text('CC=/usr/bin/gcc\nCFLAGS=-O2\nOBJECTS=main.o '+' '.join(f'unit{i}.o' for i in range(8))+'\nall: program\nprogram: $(OBJECTS)\n\t$(CC) $(OBJECTS) -o $@\n')
Path('/home/retroos/ext4-temp').mkdir(exist_ok=True)
rows=[]
for label,flags,temporary in [('ram-first','-O2','/tmp'),('ext4','-O2','/home/retroos/ext4-temp'),('ram-repeat','-O2','/tmp'),('retain','-O2 -save-temps=obj','/tmp'),('pipe','-O2 -pipe','/tmp')]:
    Path('/home/retroos/stage').write_text(label)
    env=os.environ.copy(); env['TMPDIR']=temporary
    start=time.monotonic_ns()
    result=subprocess.run(['/usr/bin/make','-j1','-B','CFLAGS='+flags],cwd=work,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    row={'label':label,'ns':time.monotonic_ns()-start,'status':result.returncode,'stdout':result.stdout.decode(errors='replace'),'stderr':result.stderr.decode(errors='replace')}
    rows.append(row); Path('/home/retroos/results.json').write_text(json.dumps(rows,indent=2))
    print('BUILD_CACHE',label,round(row['ns']/1e9,3),result.returncode,flush=True)
    if result.returncode: raise RuntimeError(row)
    result=subprocess.run([str(work/'program')],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    assert result.returncode==0 and result.stdout==b'PROJECT_BUILD_PASS\n',result
Path('/home/retroos/stage').write_text('done')
'''

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--work-dir',type=Path,default=ROOT/'build/ci/cache-invalidation-build')
    parser.add_argument('--boot-image',type=Path,default=ROOT/'bazel-bin/boot_disk.bin')
    parser.add_argument('--label',default='after')
    parser.add_argument('--prepare-only',action='store_true')
    parser.add_argument('--shape-directories',action='store_true',help='Match the host tool-directory entry counts using inert empty files')
    args=parser.parse_args(); work=args.work_dir.resolve(); work.mkdir(parents=True,exist_ok=True)
    base=work/'native-root.ext4'; home=work/'c'
    if not base.exists():
        (home/'RETROOS').mkdir(parents=True,exist_ok=True)
        shutil.copyfile(ROOT/'etc/RETROOS.INI',home/'RETROOS/RETROOS.INI')
        (home/'benchmark.py').write_text(BENCHMARK)
        (home/'run.sh').write_text('export HOME=/home/retroos MALLOC_ARENA_MAX=2\n/usr/bin/python3 /home/retroos/benchmark.py > /home/retroos/bench.out 2> /home/retroos/bench.err\nr=$?\nprintf "%s\\n" "$r" > /home/retroos/status\nexit "$r"\n')
        native_program_profile.prepare(work,home,False,extra_binaries=['/usr/bin/make'],image_bytes=1024**3)
    if (home/'benchmark.py').read_text() != BENCHMARK:
        raise ValueError('Fixture script changed; use a fresh --work-dir')
    if args.shape_directories:
        shaped=work/'shaped-root.ext4'
        if not shaped.exists():
            counts={}
            for name in ('/usr/bin','/usr/lib/x86_64-linux-gnu'):
                host=Path(name); directory=work/'native-root'/name.lstrip('/')
                count=len(list(host.iterdir())); present=len(list(directory.iterdir()))
                counts[name]={'host':count,'fixture_before':present}
                for index in range(max(0,count-present)):
                    (directory/f'.cache-bench-{index:05}').touch()
            (work/'directory-shape.json').write_text(json.dumps(counts,indent=2))
            with shaped.open('wb') as output: output.truncate(1024**3)
            subprocess.run(['mkfs.ext4','-q','-F','-d',str(work/'native-root'),str(shaped)],check=True)
        base=shaped
    if args.prepare_only: print(base);return
    run=work/args.label;run.mkdir(exist_ok=True)
    image=run/'data.ext4';subprocess.run(['cp','--reflink=auto','--sparse=always',str(base),str(image)],check=True)
    boot=prepare_boot(run,image,'[environment]\nTEST=/home/retroos/RETROOS/SHELL.ELF /home/retroos/run.sh\n',boot_image=args.boot_image)
    with (run/'klog.txt').open('w') as output:
        result=subprocess.run(['qemu-system-x86_64','-accel','kvm','-cpu','host','-m','4096','-display','none','-serial','none','-no-reboot','-nic','none','-debugcon','stdio','-drive',f'file={boot},format=raw,snapshot=on','-drive',f'file={image},format=raw,if=none,id=data','-device','nvme,drive=data,serial=CACHEBUILD'],stdout=output,stderr=subprocess.STDOUT,timeout=480)
    for name in ('status','stage','results.json','bench.out','bench.err'):
        subprocess.run(['debugfs','-R',f'dump /home/retroos/{name} {run/name}',str(image)],capture_output=True,check=True)
    assert result.returncode==0 and (run/'status').read_text().strip()=='0',str(run)
    rows=json.loads((run/'results.json').read_text())
    assert len(rows)==5 and all(row['status']==0 for row in rows),rows
    for row in rows: print(row['label'],round(row['ns']/1e9,3))

if __name__=='__main__':main()
