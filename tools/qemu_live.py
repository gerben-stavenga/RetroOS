#!/usr/bin/env python3
"""Private Samba exports for a QEMU view of the live Linux root and RetroOS C:."""
import argparse
import json
import os
from pathlib import Path
import pwd
import secrets
import shutil
import signal
import socket
import subprocess
import time

from vm_mount_config import split_configuration, volumes

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / 'build/qemu-live.json'
LOCAL = ROOT / 'build/qemu-samba/root'


def command(args, **kwargs):
    result = subprocess.run(list(map(str, args)), capture_output=True, **kwargs)
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors='replace').strip() or f'{args[0]} failed')
    return result.stdout


def binaries():
    smbd = os.environ.get('RETROOS_SMBD') or shutil.which('smbd')
    pdbedit = os.environ.get('RETROOS_PDBEDIT') or shutil.which('pdbedit')
    existing = Path.home() / '.local/lib/retroos-samba'
    if not smbd and (existing / 'smbd').is_file():
        smbd = str(existing / 'smbd')
    if not pdbedit and (existing / 'pdbedit').is_file():
        pdbedit = str(existing / 'pdbedit')
    if not smbd and (LOCAL / 'usr/sbin/smbd').is_file():
        smbd = str(LOCAL / 'usr/sbin/smbd')
    if not pdbedit and (LOCAL / 'usr/bin/pdbedit').is_file():
        pdbedit = str(LOCAL / 'usr/bin/pdbedit')
    if not smbd or not pdbedit:
        raise RuntimeError('Samba tools missing; run python3 tools/qemu_live.py setup')
    return smbd, pdbedit


def setup(root, c_root):
    root, c_root = root.resolve(), c_root.resolve()
    for path in (root, c_root):
        if not path.is_dir() or any(c in str(path) for c in '\n\r\0%'):
            raise ValueError('Share paths must be existing directories without Samba substitutions')
    if not (c_root / 'RETROOS/RETROOS.INI').is_file():
        raise ValueError(f'{c_root}/RETROOS/RETROOS.INI is missing')
    try:
        binaries()
    except RuntimeError:
        # Keep the host's service/configuration untouched. On Debian/Ubuntu,
        # extract server utilities locally, using the existing Samba libraries.
        packages = ROOT / 'build/qemu-samba/packages'
        packages.mkdir(parents=True, exist_ok=True)
        LOCAL.mkdir(parents=True, exist_ok=True)
        command(['apt-get', 'download', 'samba', 'samba-common-bin', 'samba-common'], cwd=packages)
        for package in packages.glob('*.deb'):
            command(['dpkg-deb', '-x', package, LOCAL])
    smbd, pdbedit = binaries()
    command([smbd, '--version'])
    command([pdbedit, '--version'])
    PROFILE.parent.mkdir(parents=True, exist_ok=True)
    profile = {'root': str(root), 'c_root': str(c_root)}
    if root == Path('/'):
        profile['session_home'] = str(Path.home().resolve())
    PROFILE.write_text(json.dumps(profile, indent=2) + '\n')
    PROFILE.chmod(0o600)
    print(f'Configured QEMU live files: / = {root} (read-only), C: = {c_root} (writable)')
    print('Launch with ./run.sh qemu --live-root. Add --kvm to use hardware acceleration.')


def configuration(root, c_root, work, port, username):
    # Writable connections are exposed through subdirectory views.
    # Serving the host namespace lets ordinary Samba symlink
    # handling resolve existing C: application links without wide-links mode.
    return f'''[global]
server role = standalone server
security = user
workgroup = WORKGROUP
netbios name = RETROQEMU
interfaces = 127.0.0.1
bind interfaces only = yes
disable netbios = yes
smb ports = {port}
server min protocol = SMB2_02
server max protocol = SMB2_10
server signing = mandatory
unix extensions = no
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
map to guest = never
case sensitive = yes
[root]
path = {root}
read only = yes
valid users = {username}
[data]
path = /
read only = no
valid users = {username}
follow symlinks = yes
'''


def prepare(work, boot, root, c_root, port, password, startup, native_home=None,
            native_tools=None, native_tool_paths=(), session_home=None):
    username = pwd.getpwuid(os.getuid()).pw_name
    for directory in ('private', 'lock', 'cache', 'state', 'run'):
        (work / directory).mkdir(mode=0o700)
    config = work / 'smb.conf'
    config.write_text(configuration(root, c_root, work, port, username))
    config.chmod(0o600)
    _, pdbedit = binaries()
    command([pdbedit, '-t', '-a', '-u', username, '-s', config], input=(password + '\n' + password + '\n').encode())
    _, settings = split_configuration((c_root / 'RETROOS/RETROOS.INI').read_text())
    rtc = 'localtime'
    section = ''
    kept = []
    for line in settings.splitlines(keepends=True):
        stripped = line.strip()
        if stripped.startswith('['): section = stripped.lower()
        key, _, value = stripped.partition('=')
        if section == '[clock]' and key.strip() == 'rtc' and value.strip() == 'utc': rtc = 'utc'
        if startup and section == '[environment]' and key.strip().upper() == 'TEST': continue
        kept.append(line)
    settings = ''.join(kept)
    (work / 'rtc-base').write_text(rtc)
    if startup:
        if any(c in startup for c in '\n\r\0'):
            raise ValueError('Startup command must be one line')
        settings += '\n[environment]\nTEST=' + startup + '\n'
    guest_c_root = str(c_root) if session_home else '/home/retroos'
    shares = [('root', '/', 'ro', None)]
    if session_home and Path('/tmp') not in (session_home, c_root):
        shares.append(('data', '/tmp', 'rw', '/tmp'))
    if session_home and session_home != c_root:
        shares.append(('data', str(session_home), 'rw', session_home))
    if not native_home:
        shares.append(('data', guest_c_root, 'rw', c_root))
    for share, path, access, subdir in shares:
        settings += (f'\n[smb]\nserver=10.0.2.2\nport={port}\nshare={share}\n'
                     f'username={username}\npassword={password}\npath={path}\naccess={access}\n')
        if subdir is not None:
            settings += f'subdir={subdir}\n'
    boot_config = '[bundle]\nsource=UUID=5E77-0002\nsubdir=/\n'
    if session_home:
        boot_config += (f'runtime_only=true\n\n[session]\nhome={session_home}\nuid={os.getuid()}\ngid={os.getgid()}\n'
                        'host_paths=true\n\n')
        if session_home != c_root:
            boot_config += (f'[mount "home"]\nsource=bundle\npath={session_home}\n'
                            'access=ram\nsubdir=/\n\n')
    else:
        boot_config += '\n'
    boot_config += (f'[mount "data"]\nsource=bundle\npath={guest_c_root}\n'
                    'drive=C\naccess=ram\nsubdir=/\n')
    if native_home:
        ident = next(ident for kind, ident in volumes(native_home) if kind == 'ext4')
        boot_config = ('[bundle]\nsource=UUID=5E77-0002\nsubdir=/\n\n'
                       f'[mount "data"]\nsource=UUID={ident}\npath=/home/retroos\n'
                       'drive=C\naccess=rw\nsubdir=/home/retroos\ngrant=/home/retroos\n')
    if native_tools:
        ident = next(ident for kind, ident in volumes(native_tools) if kind == 'ext4')
        for index, binding in enumerate(native_tool_paths):
            boot_config += (f'\n[mount "compiler{index}"]\nsource=UUID={ident}\n'
                            f'path={binding["path"]}\nsubdir={binding["subdir"]}\naccess=ro\n')
    # Both files are on the disposable boot image; persistent host INIs are
    # never edited and per-launch SMB credentials never enter source control.
    for name, text in [('BOOT.INI', boot_config), ('RETROOS.INI', settings)]:
        target = work / name
        target.write_text(text)
        target.chmod(0o600)
        command(['mcopy', '-o', '-i', str(boot) + '@@1048576', target, '::RETROOS/' + name])
        if native_home and name == 'RETROOS.INI':
            # Startup reads settings from C: once that native mount is active.
            # The caller supplies a disposable image, prepared before VM launch.
            command(['debugfs', '-w', '-R', 'rm /home/retroos/RETROOS/RETROOS.INI', native_home])
            command(['debugfs', '-w', '-R', f'write {target} /home/retroos/RETROOS/RETROOS.INI', native_home])


def serve(work, boot, startup, profile_path):
    if os.geteuid() == 0:
        raise ValueError('Run QEMU live sharing as your normal user, not root')
    profile = json.loads(profile_path.read_text())
    root, c_root = Path(profile['root']), Path(profile['c_root'])
    session_home = profile.get('session_home')
    if session_home is None and root == Path('/') and profile_path.resolve() == PROFILE.resolve():
        session_home = Path.home()
    if session_home is not None:
        if root != Path('/') or profile.get('native_home_image'):
            raise ValueError('session_home requires the live host root and DOS directory')
        session_home, c_root = Path(session_home).resolve(), c_root.resolve()
        for path in (session_home, c_root):
            if path == Path('/') or not path.is_dir() or any(c in str(path) for c in '\n\r\0%'):
                raise ValueError(f'Invalid live session directory: {path}')
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    password = secrets.token_hex(32)
    prepare(work, boot, root, c_root, port, password, startup, profile.get("native_home_image"),
            profile.get("native_tool_image"), profile.get("native_tool_paths", ()), session_home)
    smbd, _ = binaries()
    def interrupted(number, _frame):
        raise SystemExit(128 + number)
    for number in (signal.SIGTERM, signal.SIGINT):
        signal.signal(number, interrupted)
    with (work / 'samba-stderr').open('wb') as errors:
        server = subprocess.Popen([smbd, '-F', '--no-process-group', '--debug-stdout', '-d', '1', '-s', str(work / 'smb.conf')],
                                  stdin=subprocess.DEVNULL, stdout=errors, stderr=errors, start_new_session=True)
        try:
            deadline = time.monotonic() + 10
            while True:
                if server.poll() is not None:
                    detail = (work / 'samba.log').read_text(errors='replace') if (work / 'samba.log').exists() else ''
                    raise RuntimeError(f'Private Samba server exited ({server.returncode}): ' + detail[-1500:] + (work / 'samba-stderr').read_text(errors='replace')[-1500:])
                try:
                    with socket.create_connection(('127.0.0.1', port), timeout=.2):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError('Private Samba server did not start')
                    time.sleep(.05)
            (work / 'smb-ready').write_text(str(port))
            home_source = profile.get('native_home_image', str(c_root))
            print(f'Live files: / = {root} (read-only SMB), C: = {home_source} (writable)', flush=True)
            server.wait()
        finally:
            try:
                os.killpg(server.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(server.pid, signal.SIGKILL)
                server.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    install = commands.add_parser('setup')
    install.add_argument('--root', type=Path, default=Path('/'))
    install.add_argument('--c-root', type=Path, default=Path.home() / 'DOS')
    start = commands.add_parser('serve')
    start.add_argument('--work', type=Path, required=True)
    start.add_argument('--boot-image', type=Path, required=True)
    start.add_argument('--command', default='')
    start.add_argument('--profile', type=Path, default=PROFILE)
    args = parser.parse_args()
    try:
        if args.action == 'setup':
            setup(args.root, args.c_root)
        else:
            serve(args.work.resolve(), args.boot_image.resolve(), args.command, args.profile)
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(1, f'qemu_live: {error}\n')


if __name__ == '__main__':
    main()
