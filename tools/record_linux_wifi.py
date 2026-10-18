#!/usr/bin/env python3
"""Prepare a separate Linux boot image to record ath12k initialization.

Never reloads the NIC or changes GRUB defaults. Requires initramfs-tools,
tracefs kprobes, x86-64, and bpftool. The capture contains startup diagnostics.
"""
import argparse
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import tempfile


TRACE = Path('/sys/kernel/tracing')
GROUP = 'retroos_wifi'
IMAGE_SUFFIX = '-retroos-wifi-v2'


def offsets():
    raw = subprocess.check_output([
        'bpftool', 'btf', 'dump', 'file', '/sys/kernel/btf/vmlinux',
        'format', 'raw'], text=True)
    result = {}
    for structure, fields in [('sk_buff', ['len', 'data']), ('socket', ['sk']),
                              ('sock', ['__sk_common']), ('sock_common', ['skc_family']),
                              ('kvec', ['iov_base', 'iov_len'])]:
        block = re.search(rf"STRUCT '{structure}'[^\n]*\n((?:\t[^\n]*\n)+)", raw)
        if not block:
            raise RuntimeError(f'{structure} missing from kernel BTF')
        for name in fields:
            match = re.search(rf"'{name}' .*bits_offset=(\d+)", block[1])
            if not match or int(match[1]) % 8:
                raise RuntimeError(f'cannot resolve {structure}.{name}')
            result[name] = int(match[1]) // 8
    return result


def probes(layout):
    # x86-64 kernel ABI: arguments are di, si, dx, cx, r8, r9.
    # Unlike $argN / BTF-aware $retval, raw registers also work when the
    # target module is absent during early-boot probe registration.
    length = f"+{layout['len']}(%si):u32"
    data = f"+{layout['data']}(%si)"
    return [
        f'p:{GROUP}/wmi_command ath12k:ath12k_wmi_cmd_send cmd=%dx:u32 length={length}',
        f'p:{GROUP}/wmi_init ath12k:ath12k_wmi_cmd_send cmd=%dx:u32 length={length} '
        f'words0=+0({data}):x32[64] words1=+256({data}):x32[18]',
        f'p:{GROUP}/pci_write ath12k:ath12k_pci_write32 offset=%si:x32 value=%dx:x32',
        f'p:{GROUP}/qmi_request qmi_helpers:qmi_send_request message=%cx:x32 capacity=%r8:u64',
        # QMI uses one kvec at kernel_sendmsg(), after TLV encoding. A connected
        # QRTR socket has NULL msg_name, so inspect socket.sk's family instead.
        f'p:{GROUP}/qmi_wire kernel_sendmsg '
        f"family=+{layout['__sk_common'] + layout['skc_family']}(+{layout['sk']}(%di)):u16 "
        f"segments=%cx:u32 length=%r8:u64 iov_length=+{layout['iov_len']}(%dx):u64 "
        f"type=+0(+{layout['iov_base']}(%dx)):u8 message=+3(+{layout['iov_base']}(%dx)):u16 "
        f"data0=+0(+{layout['iov_base']}(%dx)):x64[64] data1=+512(+{layout['iov_base']}(%dx)):x64[64]",
        f'p:{GROUP}/htc_tx ath12k:ath12k_htc_send endpoint=%si:u32 '
        f"length=+{layout['len']}(%dx):u32 data0=+0(+{layout['data']}(%dx)):x64[8]",
        f'p:{GROUP}/htc_rx ath12k:ath12k_htc_rx_completion_handler '
        f"length={length} endpoint=+0({data}):u8 data0=+0({data}):x64[8]",
        f'r:{GROUP}/ready ath12k:ath12k_wmi_wait_for_unified_ready result=%ax:s32',
    ]


def capture_settings():
    ids = ' || '.join(f'message == {value}' for value in
                     (0x20, 0x34, 0x36, 0x24, 0x2f, 0x23, 0x22, 0x3c, 0x57))
    return [
        (f'events/{GROUP}/wmi_init/filter', 'cmd == 1 && length == 328'),
        (f'events/{GROUP}/qmi_wire/filter',
         f'family == 42 && segments == 1 && type == 0 && length >= 7 && length <= 1024 && iov_length >= 7 && iov_length <= 1024 && ({ids})'),
        (f'events/{GROUP}/htc_tx/filter', 'endpoint == 0 && length >= 8 && length <= 64'),
        (f'events/{GROUP}/htc_rx/filter', 'endpoint == 0 && length >= 16 && length <= 64'),
        (f'events/{GROUP}/ready/trigger', 'traceoff:1 if result == 0'),
    ]


def put(path, text):
    Path(path).write_text(text + '\n')


def probe_command(command):
    # TextIO append mode seeks to EOF on open. kprobe_events uses seq_lseek,
    # which rejects SEEK_END with EINVAL before any command is written.
    # Keep O_APPEND (and omit O_TRUNC) without Python's implicit seek.
    write_control(TRACE / 'kprobe_events', command + '\n')


def write_control(path, text):
    data = text.encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC)
    try:
        if os.write(descriptor, data) != len(data):
            raise RuntimeError(f'short write to kernel control file: {path}')
    finally:
        os.close(descriptor)


def tracefs():
    if not (TRACE / 'kprobe_events').exists():
        subprocess.run(['mount', '-t', 'tracefs', 'tracefs', str(TRACE)], check=True)


def validate(definitions):
    """Register disabled probes, checking syntax without collecting events."""
    tracefs()
    validation_group = GROUP + '_check'
    if (TRACE / 'events' / validation_group).exists():
        raise RuntimeError('existing recorder validation probes found; refusing to replace them')
    registered = []
    instance = TRACE / 'instances' / (GROUP + '_validate')
    if instance.exists():
        raise RuntimeError(f'validation instance already exists: {instance}')
    created_instance = False
    try:
        for definition in definitions:
            definition = definition.replace(f':{GROUP}/', f':{validation_group}/', 1)
            try:
                probe_command(definition)
            except OSError as error:
                try:
                    details = '\n'.join((TRACE / 'error_log').read_text().splitlines()[-20:])
                except OSError:
                    details = 'Kernel tracing error log unavailable.'
                raise RuntimeError(f'Could not install probe:\n{definition}\n{error}\n{details}') from error
            registered.append(definition.split()[0].split(':', 1)[1])
        instance.mkdir()
        created_instance = True
        for relative, value in capture_settings():
            relative = relative.replace(f'events/{GROUP}/', f'events/{validation_group}/', 1)
            try:
                put(instance / relative, value)
            except OSError as error:
                raise RuntimeError(f'Kernel rejected capture setting {relative}: {value}\n{error}') from error
    finally:
        if created_instance:
            instance.rmdir()
        for name in reversed(registered):
            probe_command('-:' + name)


def startup(definitions):
    commands = '\n'.join(
        f"printf '%s\\n' {shlex.quote(line)} >> \"$t/kprobe_events\" || exit 0"
        for line in definitions)
    settings = '\n'.join(
        f"printf '%s\\n' {shlex.quote(value)} > \"$i/{relative}\" || exit 0"
        for relative, value in capture_settings())
    return '''#!/bin/sh
case "$1" in prereqs) exit 0;; esac
# Diagnostic failure must never prevent the normal Linux boot.
(
t=/sys/kernel/tracing
mount -t tracefs tracefs "$t" 2>/dev/null || true
[ -w "$t/kprobe_events" ] || exit 0
''' + commands + '''
mkdir -p "$t/instances/retroos_wifi" || exit 0
i="$t/instances/retroos_wifi"
echo 0 > "$i/tracing_on"
echo 4096 > "$i/buffer_size_kb" || exit 0
''' + settings + '''
echo 1 > "$i/events/retroos_wifi/enable" || exit 0
echo 1 > "$i/tracing_on"
) || true
exit 0
'''


def executable(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(0o755)
    subprocess.run(['sh', '-n', str(path)], check=True)


def grub_entry(config, release):
    """Copy a normal entry, retaining its disk search, root and kernel options."""
    lines = config.splitlines(keepends=True)
    kernel = re.compile(r'^\s*linux(?:efi)?\s+\S*/vmlinuz-' + re.escape(release) + r'(?:\s|$)')
    initrd = re.compile(r'(?<![^\s/])initrd\.img-' + re.escape(release) + r'(?=[\s\'\"]|$)')
    for index, line in enumerate(lines):
        match = re.match(r'^(\s*)menuentry\s', line)
        if not match or 'retroos-linux-wifi-capture' in line:
            continue
        end = next((at for at in range(index + 1, len(lines))
                    if lines[at].strip() == '}'
                    and lines[at].startswith(match[1] + '}')), None)
        if end is None:
            continue
        body = lines[index + 1:end]
        linux = next((row for row in body if kernel.match(row)), '')
        if not linux or re.search(r'(?:^|\s)(?:recovery|single)(?:\s|$)', linux):
            continue
        replaced = 0
        output = []
        for row in body:
            if row.strip() == 'savedefault':
                continue
            if re.match(r'^\s*initrd(?:efi)?\s', row):
                row, count = initrd.subn(lambda found: found[0] + IMAGE_SUFFIX, row)
                replaced += count
            output.append(row)
        if replaced != 1:
            continue
        return (f"menuentry 'Linux Wi-Fi startup capture ({release})' "
                "--id retroos-linux-wifi-capture {\n" + ''.join(output) + '}\n')
    raise RuntimeError(f'no normal Linux GRUB entry with kernel and initrd for {release}')


def install_grub(release):
    image = Path('/boot') / f'initrd.img-{release}{IMAGE_SUFFIX}'
    if not image.is_file():
        raise RuntimeError(f'{image} missing; run prepare first')
    entry = grub_entry(Path('/boot/grub/grub.cfg').read_text(), release)
    subprocess.run(['grub-script-check'], input=entry, text=True, check=True)
    target = Path('/etc/grub.d/43_retroos_wifi_capture')
    content = '#!/bin/sh\nexec tail -n +3 "$0"\n' + entry
    previous = target.read_bytes() if target.exists() else None
    previous_mode = target.stat().st_mode & 0o777 if target.exists() else None
    try:
        target.write_text(content)
        target.chmod(0o755)
        subprocess.run(['update-grub'], check=True)
    except (OSError, subprocess.CalledProcessError):
        if previous is None:
            target.unlink(missing_ok=True)
        else:
            target.write_bytes(previous)
            target.chmod(previous_mode)
        subprocess.run(['update-grub'], check=False)
        raise
    print(f'Installed GRUB entry: Linux Wi-Fi startup capture ({release})')
    print('Select it on your next boot, then run this tool with collect.')


def prepare():
    if platform.machine() != 'x86_64':
        raise RuntimeError('this recorder currently supports x86-64 only')
    release = platform.release()
    image = Path('/boot') / f'initrd.img-{release}{IMAGE_SUFFIX}'
    if image.exists():
        install_grub(release)
        return
    definitions = probes(offsets())
    validate(definitions)
    # A private configuration lets us explicitly order tracing before udev
    # without editing the installed configuration or its boot image.
    with tempfile.TemporaryDirectory(prefix='retroos-wifi-') as temp:
        config = Path(temp) / 'config'
        shutil.copytree('/etc/initramfs-tools', config, symlinks=True)
        original = config / 'scripts/init-top/udev'
        source = original if original.exists() else Path('/usr/share/initramfs-tools/scripts/init-top/udev')
        original_text = source.read_text()
        prerequisites = subprocess.check_output([str(source), 'prereqs'], text=True).split()
        executable(config / 'scripts/init-top/retroos-wifi-trace', startup(definitions))
        executable(original, '''#!/bin/sh
case "$1" in prereqs) printf '%s\\n' '''
                   + shlex.quote(' '.join(['retroos-wifi-trace', *prerequisites]))
                   + '''; exit 0;; esac
exec /scripts/retroos-original-udev "$@"
''')
        # The original udev script is outside init-top to avoid running it twice.
        executable(config / 'scripts/retroos-original-udev', original_text)
        temporary_image = Path(temp) / 'initrd.img'
        subprocess.run(['mkinitramfs', '-d', str(config), '-o', str(temporary_image), release], check=True)
        # Verify both payload and explicit dependency survived image creation.
        unpacked = Path(temp) / 'unpacked'
        subprocess.run(['unmkinitramfs', str(temporary_image), str(unpacked)], check=True)
        orders = list(unpacked.rglob('scripts/init-top/ORDER'))
        if len(orders) != 1:
            raise RuntimeError('could not verify init-top order in generated image')
        order = orders[0].read_text().splitlines()
        trace_index = next(i for i, line in enumerate(order) if line.startswith('/scripts/init-top/retroos-wifi-trace '))
        udev_index = next(i for i, line in enumerate(order) if line.startswith('/scripts/init-top/udev '))
        if trace_index >= udev_index:
            raise RuntimeError('recorder must run before udev')
        staged_image = image.with_name(image.name + '.new')
        try:
            shutil.copyfile(temporary_image, staged_image)
            staged_image.chmod(0o600)
            staged_image.replace(image)
        finally:
            staged_image.unlink(missing_ok=True)
    print(f'Created {image}')
    install_grub(release)


def collect(output):
    tracefs()
    instance = TRACE / 'instances' / GROUP
    if not instance.exists():
        raise RuntimeError('no capture found; boot the diagnostic initramfs first')
    if output is None:
        output = Path('build/linux-wifi-trace')
        index = 2
        while output.exists():
            output = Path(f'build/linux-wifi-trace-{index}')
            index += 1
    if output.exists():
        raise RuntimeError(f'output directory already exists: {output}')
    output.mkdir(parents=True, mode=0o700)
    was_running = (instance / 'tracing_on').read_text().strip()
    put(instance / 'tracing_on', '0')
    from inspect_linux_wifi_trace import sanitize_line, decode
    with (instance / 'trace').open() as src, (output / 'trace.txt').open('w') as dst:
        for line in src:
            dst.write(sanitize_line(line))
    stats = []
    for path in sorted((instance / 'per_cpu').glob('cpu*/stats')):
        stats.append(path.parent.name + '\n' + path.read_text())
    put(output / 'buffer-stats.txt', '\n'.join(stats))
    put(output / 'metadata.txt', f'kernel={platform.release()}\ntracing_on_before_collect={was_running}\n'
        'INIT dump is 82 little-endian DWORDs, only for cmd=1 and skb length=328.\n'
        'QMI capacity is the maximum encoded buffer size, not wire length.\n'
        'v2 qmi_wire: encoded requests, selected WLANFW message IDs, <=1024 bytes.\n'
        'v2 htc_tx: control payload; htc_rx: control frame with HTC header, <=64 bytes.\n'
        'Fixed-fetch padding is discarded before trace.txt is saved.')
    decode(output / 'trace.txt', output / 'packets')
    with (output / 'kernel-log.txt').open('w') as stream:
        subprocess.run(['journalctl', '-k', '-b', '--no-pager'], stdout=stream, check=True)
    # Output is root-owned so reading it does not require loosening permissions
    # on tracefs. Give the invoking sudo user ownership of just these artifacts.
    if 'SUDO_UID' in os.environ and 'SUDO_GID' in os.environ:
        for path in [output, *output.rglob('*')]:
            os.chown(path, int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID']))
    print(f'Saved {output.resolve()}')
    print('Check trace.txt for ready: result=0 and wmi_init; buffer-stats.txt for overruns.')
    print('A normal Linux boot clears the probes. The separate diagnostic initrd can then be removed.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['prepare', 'grub', 'collect'])
    parser.add_argument('--output', type=Path, help='capture directory (default: next unused build/linux-wifi-trace[-N])')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('run with sudo; this accesses tracefs and /boot')
    try:
        if args.action == 'prepare':
            prepare()
        elif args.action == 'grub':
            install_grub(platform.release())
        else:
            collect(args.output)
    except (OSError, RuntimeError, subprocess.CalledProcessError, StopIteration) as error:
        parser.exit(1, f'{error}\n')


if __name__ == '__main__':
    main()
