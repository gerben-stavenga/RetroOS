"""Measure Doom's core-0 profile or a fixed 350-tic timedemo in isolated QEMU.

Examples:
  python3 test/doom_media_profile.py --cpus 2 --mode profile --label async
  python3 test/doom_media_profile.py --cpus 2 --mode osd --label async-osd
  python3 test/doom_media_profile.py --cpus 2 --mode timedemo --label async-fps

Run variants sequentially, with the same data disk and music configuration.
Profile mode plays demo1 at its normal clock; timedemo runs the same fixed
prefix unthrottled with profiling disabled. OSD mode opens F12's Debug tab.
Result JSON, boot image, guest log and recorded audio remain in the printed
temporary directory. No persistent game settings or disk contents are changed.
"""
import argparse
import hashlib
import sys
import re
import time
import json
import subprocess
import shutil
import tempfile
import importlib.util
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'test'))
from boot_fixture import prepare_boot
spec = importlib.util.spec_from_file_location('serial', ROOT / 'tools/86box_mcp.py')
serial = importlib.util.module_from_spec(spec)
spec.loader.exec_module(serial)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--label', default='media')
    parser.add_argument('--cpus', type=int, default=2)
    parser.add_argument('--mode', choices=['profile', 'osd', 'timedemo'], default='profile')
    parser.add_argument('--no-build', action='store_true', help='Use the existing Bazel images')
    options = parser.parse_args()
    if options.cpus < 1:
        parser.error('--cpus must be positive')
    label = re.sub('[^A-Za-z0-9_-]', '_', options.label)
    cpus = options.cpus
    mode = options.mode
    if not options.no_build:
        subprocess.run(['bazelisk', 'build', '//:boot_disk', '//:data_disk'], cwd=ROOT, check=True)
    work = Path(tempfile.mkdtemp(prefix='retroos-perf-' + label + '-'))
    print(work, flush=True)
    data = work / 'data.img'
    subprocess.run(['cp', '--reflink=auto', str(ROOT / 'bazel-bin/data_disk.bin'), str(data)], check=True)
    data.chmod(384)
    if mode == 'timedemo':
        import struct
        with data.open('rb') as stream:
            mbr = stream.read(512)
        start = struct.unpack_from('<I', mbr, 454)[0] if mbr[450] else 0
        wad = work / 'DOOM1.WAD'
        subprocess.run(['mcopy', '-i', f'{data}@@{start * 512}', '::GAMES/DOOMS/DOOM1.WAD', str(wad)], check=True)
        raw = wad.read_bytes()
        count, directory = struct.unpack_from('<II', raw, 4)
        demo = None
        for index in range(count):
            offset, size, name = struct.unpack_from('<II8s', raw, directory + 16 * index)
            if name.rstrip(b'\x00') == b'DEMO1':
                demo = raw[offset:offset + size]
                break
        assert demo is not None, 'DOOM1.WAD has no DEMO1'
        assert len(demo) >= 13 + 350 * 4 + 1
        assert demo[0] == 109 and demo[9:13] == bytes([1, 0, 0, 0]) and (demo[-1] == 128) and ((len(demo) - 14) % 4 == 0)
        short = work / 'PERF.LMP'
        short.write_bytes(demo[:13 + 350 * 4] + bytes([128]))
        with data.open('rb') as stream:
            mbr = stream.read(512)
        start = struct.unpack_from('<I', mbr, 454)[0] if mbr[450] else 0
        subprocess.run(['mcopy', '-o', '-i', f'{data}@@{start * 512}', str(short), '::GAMES/DOOMS/PERF.LMP'], check=True)
    boot = prepare_boot(work, data)
    shutil.copyfile('/usr/share/OVMF/OVMF_VARS_4M.fd', work / 'vars.fd')
    cmdline = 'GAMES/DOOMS/DOOM.EXE -' + ('timedemo' if mode == 'timedemo' else 'playdemo') + (' perf' if mode == 'timedemo' else ' demo1')
    args = ['qemu-system-x86_64', '-accel', 'kvm', '-cpu', 'host', '-smp', str(cpus), '-M', 'q35', '-m', '512', '-nodefaults', '-device', 'bochs-display', '-device', 'qemu-xhci', '-display', 'none', '-nic', 'none', '-serial', 'none', '-chardev', f'socket,id=mcp,path={work}/mcp.sock,server=on,wait=off', '-serial', 'chardev:mcp', '-fw_cfg', 'name=opt/mcp,string=com2', '-fw_cfg', 'name=opt/cmdline,string=' + cmdline, '-fw_cfg', 'name=opt/cwd,string=GAMES/DOOMS', '-drive', 'if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd', '-drive', f'if=pflash,format=raw,file={work}/vars.fd', '-drive', f'file={boot},if=none,id=boot,format=raw,snapshot=on', '-device', 'piix3-ide,id=boot-ide', '-device', 'ide-hd,drive=boot,bus=boot-ide.0,unit=0,bootindex=1', '-drive', f'file={data},if=none,id=data,format=raw,snapshot=on', '-device', 'ide-hd,drive=data,bus=ide.0', '-audiodev', f'wav,id=snd0,path={work}/audio.wav', '-device', 'intel-hda', '-device', 'hda-duplex,audiodev=snd0', '-debugcon', f'file:{work}/guest.log', '-no-reboot']
    log = work / 'guest.log'
    results = {'label': label, 'cpus': cpus, 'mode': mode, 'work': str(work), 'commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(), 'diff_sha256': hashlib.sha256(subprocess.check_output(['git', 'diff', 'HEAD'], cwd=ROOT)).hexdigest(), 'boot_sha256': hashlib.sha256(boot.read_bytes()).hexdigest()}
    if mode == 'timedemo':
        results['demo_sha256'] = hashlib.sha256(short.read_bytes()).hexdigest()
    with (work / 'stderr').open('w') as err:
        p = subprocess.Popen(args, stdout=err, stderr=err)
        try:
            deadline = time.monotonic() + 90
            while 'ST_Init' not in (text := (log.read_text(errors='replace') if log.exists() else '')):
                if p.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError(text[-4000:])
                time.sleep(0.05)
            assert 'midi: GM bank ROM:' in text, 'missing MIDI bank'
            if mode == 'timedemo':
                deadline = time.monotonic() + 240
                while not (m := re.search('(\\d+) gametics in (\\d+) realtics', log.read_text(errors='replace'))):
                    if p.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError(log.read_text(errors='replace')[-4000:])
                    time.sleep(0.05)
                results['gametics'] = int(m[1])
                assert results['gametics'] == 350
                results['realtics'] = int(m[2])
                results['fps'] = int(m[1]) * 35 / int(m[2])
            else:
                control = serial.SerialControl(None, str(work / 'mcp.sock'))
                time.sleep(2)
                if mode == 'osd':
                    control.request('key f12')
                    time.sleep(0.2)
                    for _ in range(3):
                        control.request('key tab')
                        time.sleep(0.1)
                    time.sleep(0.3)
                results['start'] = control.request('profile on')
                time.sleep(15)
                results['coarse'] = control.request('profile dump', timeout=15)
                results['execution'] = control.request('profile execution', timeout=15)
                results['top'] = control.request('profile top', timeout=15)
                control.close()
            (work / 'result.json').write_text(json.dumps(results, indent=2))
            print(json.dumps({k: v for k, v in results.items() if k not in ('top', 'execution', 'start')}), flush=True)
        finally:
            p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
if __name__ == '__main__':
    main()
