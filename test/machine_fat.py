#!/usr/bin/env python3
"""Boot the FAT machine-install layout and persist edits to both INIs."""
from pathlib import Path
import shutil
import tarfile
import os
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from grub_module_install import seed_c_files
from machine_install import grub_entries, boot_configuration, normalize_runtime, runtime_filter


def run(*args):
    subprocess.run(list(map(str, args)), cwd=ROOT, check=True, stdout=subprocess.DEVNULL)


def contents(image, name, kind):
    if kind == 'fat':
        return subprocess.check_output(['mtype', '-i', str(image), '::RETROOS/' + name])
    return subprocess.check_output(['debugfs', '-R', 'cat /RETROOS/' + name, str(image)], stderr=subprocess.DEVNULL)


def boot(work, iso, disk, expected):
    log = work / 'guest.log'
    log.unlink(missing_ok=True)
    process = subprocess.Popen([
        'qemu-system-i386', '-m', '128', '-cdrom', str(iso), '-boot', 'order=d',
        '-drive', f'file={disk},format=raw', '-display', 'none', '-serial', 'none',
        '-debugcon', f'file:{log}', '-no-reboot',
        '-fw_cfg', 'name=opt/cmdline,string=/dos/PROBE.ELF',
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline and process.poll() is None:
            text = log.read_text(errors='replace') if log.exists() else ''
            if '[mem] exit tid=1 code=' in text:
                time.sleep(1)  # let the normal disk synchronization run
                break
            time.sleep(.1)
    finally:
        process.terminate()
        process.wait(timeout=5)
    text = log.read_text(errors='replace')
    assert f'[mem] exit tid=1 code={expected}' in text, text[-5000:]
    assert '[mem] exit tid=1 code=1' not in text and 'FATAL' not in text and 'panicked' not in text, text
    assert 'Locale: it-IT' in text, text


def exercise(kind):
    with tempfile.TemporaryDirectory(prefix='retroos-machine-fat-') as directory:
        work = Path(directory)
        stage = work / 'stage'
        stage.mkdir()
        ident = 'ABCD-1234' if kind == 'fat' else 'ea8c19a0-a2e3-4d14-9fd2-6955c176122c'
        plan = {'boot_uuid': '0000-0000', 'release': '/boot/retroos/releases/test',
                'grub_release': '/boot/retroos/releases/test', 'uuid': ident, 'c_uuid': ident,
                'c_dir': '/', 'c_root': '/', 'linux_root': None, 'runtime_subdir': '/RETROOS/releases/test'}
        (stage / 'BOOT.INI').write_text(boot_configuration(plan))
        (stage / 'RETROOS.INI').write_text((ROOT / 'etc/RETROOS.INI').read_text().replace('language=en-US', 'language=it-IT'))
        home = work / 'C'
        home.mkdir()
        seed_c_files(home, stage)
        runtime = home / 'RETROOS/releases/test'
        with tarfile.open(ROOT / 'bazel-bin/machine_boot_tar.tar') as archive:
            archive.extractall(runtime, filter=runtime_filter)
        normalize_runtime(runtime)
        source = work / 'probe.c'
        source.write_text(r'''
static int call(int n,int a,int b,int c) { int r;
 __asm__ volatile("int $0x80":"=a"(r):"0"(n),"b"(a),"c"(b),"d"(c):"memory"); return r; }
static int contains(char *b,int n,char *s) {
 for(int i=0;i<n;i++) { int j=0; while(s[j] && i+j<n && b[i+j]==s[j]) j++;
  if(!s[j]) return 1; } return 0; }
void _start(void) {
 int error=10;
 // Both FAT and ext4 use the disk runtime's BusyBox root in this profile.
 char link[32];
 int l=call(85,(int)"/bin/sh",(int)link,sizeof(link));
 if(l!=7 || !contains(link,l,"busybox")) goto fail;
 error=11;
 int sh=call(5,(int)"/bin/sh",0,0); char elf[4];
 if(sh<0 || call(3,sh,(int)elf,4)!=4 || elf[0]!=127 || elf[1]!='E') goto fail;
 call(6,sh,0,0);
 error=12;
 int state=call(5,(int)"/dos/STATE.DAT",0,0), again=state>=0;
 if(again) call(6,state,0,0);
 char *paths[]={"/dos/RETROOS/RETROOS.INI","/dos/RETROOS/BOOT.INI"};
 char marker[]="\n# MACHINE_CONFIG_EDIT\n", b[8192];
 for(int i=0;i<2;i++) {
  error=20+i*10;
  int f=call(5,(int)paths[i],2,0); if(f<0) goto fail;
  error++; int n=call(3,f,(int)b,sizeof(b)); if(n<=0) goto fail;
  error++; if(again && !contains(b,n,"MACHINE_CONFIG_EDIT")) goto fail;
  error++; if(call(19,f,0,2)<0) goto fail;
  error++; if(call(4,f,(int)marker,sizeof(marker)-1)!=sizeof(marker)-1) goto fail;
  call(6,f,0,0);
 }
 error=16;
 state=call(5,(int)"/dos/STATE.DAT",0x241,0644);
 if(state<0 || call(4,state,(int)"YES",3)!=3) goto fail;
 call(6,state,0,0); call(1,again?2:0,0,0);
fail: call(1,error,0,0); for(;;) {}
}
''')
        run('gcc', '-m32', '-nostdlib', '-static', '-fno-pie', '-no-pie', source, '-o', home / 'PROBE.ELF')
        disk = work / 'data.img'
        with disk.open('wb') as stream:
            stream.truncate(64 * 1024 * 1024)
        if kind == 'fat':
            run('mkfs.fat', '-F', '32', '-i', 'ABCD1234', disk)
            run('mcopy', '-s', '-i', disk, home / 'RETROOS', '::/')
            run('mcopy', '-i', disk, home / 'PROBE.ELF', '::/')
        else:
            run('mkfs.ext4', '-q', '-F', '-U', ident, '-E',
                f'root_owner={os.getuid()}:{os.getgid()}', '-d', home, disk)
        tree = work / 'iso'
        release = tree / 'boot/retroos/releases/test'
        release.mkdir(parents=True)
        (tree / 'boot/grub').mkdir()
        shutil.copyfile(ROOT / 'bazel-bin/kernel/kernel.elf', release / 'kernel.elf')
        entries = grub_entries(plan).replace(
            'search --no-floppy --fs-uuid --set=root 0000-0000', 'set root=$bootiso')
        config = tree / 'boot/grub/grub.cfg'
        assert 'retroos.mount=' not in entries and 'retroos-base.img' not in entries
        config.write_text('set timeout=0\nset default=0\nset bootiso=$root\n' + entries)
        iso = work / 'persistent.iso'
        run('grub-mkrescue', '-o', iso, tree)
        boot(work, iso, disk, 0)
        for name in ('BOOT.INI', 'RETROOS.INI'):
            assert b'MACHINE_CONFIG_EDIT' in contents(disk, name, kind), name
        boot(work, iso, disk, 2)
        before = {name: contents(disk, name, kind) for name in ('BOOT.INI', 'RETROOS.INI')}
        config.write_text('set timeout=0\nset default=1\nset bootiso=$root\n' + entries)
        protected = work / 'protected.iso'
        run('grub-mkrescue', '-o', protected, tree)
        boot(work, protected, disk, 2)
        for name, data in before.items():
            assert contents(disk, name, kind) == data, name
        print(f'PASS: {kind} disk runtime supplies BusyBox root, persists both INIs across reboot, and protects disk edits')


def main():
    run('bazelisk', 'build', '//:machine_boot_tar')
    for kind in ('fat', 'ext4'):
        exercise(kind)


if __name__ == '__main__':
    main()
