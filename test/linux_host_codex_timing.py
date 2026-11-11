#!/usr/bin/env python3
"""Time installed Codex resume on Linux with copied private state and a PTY."""
import argparse
import errno
import fcntl
import json
import os
from pathlib import Path
import pty
import re
import select
import shutil
import signal
import sqlite3
import struct
import sys
import tempfile
import termios
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from setup_codex import DEFAULT_BINARY

ANSI = re.compile(rb'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]')


def prepare(source, home, thread):
    state = home / '.codex'
    state.mkdir(mode=0o700)
    work = home / 'work'
    work.mkdir()
    for name in ('auth.json', 'models_cache.json'):
        if (source / name).is_file():
            shutil.copyfile(source / name, state / name)
            (state / name).chmod(0o600)
    if (source / 'skills').is_dir():
        shutil.copytree(source / 'skills', state / 'skills', symlinks=True)
    for database in source.glob('*.sqlite'):
        if database.name == 'logs_2.sqlite':
            continue
        with tempfile.TemporaryDirectory() as directory:
            for suffix in ('', '-wal', '-shm'):
                original = Path(str(database) + suffix)
                if original.exists():
                    shutil.copyfile(original, Path(directory) / original.name)
            with sqlite3.connect(str(Path(directory) / database.name)) as snapshot:
                with sqlite3.connect(str(state / database.name)) as target:
                    snapshot.backup(target)
    with sqlite3.connect(str(state / 'state_5.sqlite')) as db:
        row = db.execute('select rollout_path from threads where id=?', (thread,)).fetchone()
        if not row:
            raise RuntimeError('Saved thread not found')
        rollout = Path(row[0])
        destination = state / 'sessions' / rollout.name
        destination.parent.mkdir()
        shutil.copyfile(rollout, destination)
        db.execute('update threads set rollout_path=?,cwd=? where id=?', (str(destination), str(work), thread))
    (state / 'config.toml').write_text('model="gpt-6.1-sol"\nmodel_reasoning_effort="medium"\n'
        '[features]\ndaemon_auto_start=false\n[projects.' + json.dumps(str(work)) + ']\ntrust_level="trusted"\n')
    return state, work


def run(source, thread, artifacts, index, timeout):
    with tempfile.TemporaryDirectory(prefix='retroos-host-codex-') as directory:
        home = Path(directory)
        state, work = prepare(source, home, thread)
        env = os.environ.copy()
        env.update(HOME=str(home), CODEX_HOME=str(state), TERM='xterm-256color', COLORTERM='truecolor')
        command = [str(DEFAULT_BINARY.resolve(strict=True)), '--no-daemon', '--no-alt-screen', '-C', str(work), 'resume', thread]
        start = time.perf_counter_ns()
        pid, master = pty.fork()
        if pid == 0:
            os.chdir(work)
            os.execve(command[0], command, env)
        fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack('HHHH', 25, 80, 0, 0))
        data = bytearray()
        query_tail = b''
        skipped = False
        result = None
        raw = artifacts / ('linux-codex-' + str(index) + '.pty')
        try:
            while (time.perf_counter_ns() - start) / 1e9 < timeout:
                if not select.select([master], [], [], .05)[0]:
                    continue
                try:
                    chunk = os.read(master, 65536)
                except OSError as error:
                    if error.errno == errno.EIO:
                        break
                    raise
                if not chunk:
                    break
                data.extend(chunk)
                # Respond like RetroOS's text terminal. Replies are protocol
                # responses, not commands or submitted conversation text.
                pending = query_tail + chunk
                for query, reply in [(b'\x1b[6n', b'\x1b[1;1R'), (b'\x1b[c', b'\x1b[?1;0c'),
                                     (b'\x1b[0c', b'\x1b[?1;0c'), (b'\x1b[16t', b'\x1b[6;16;9t')]:
                    if query in pending:
                        os.write(master, reply)
                query_tail = pending[-8:]
                text = ANSI.sub(b'', bytes(data[-200000:])).decode(errors='replace')
                if not skipped and re.search(r'1[.)]?\s+Update now', text) and 'Skip' in text:
                    os.write(master, b'\x1b[B\r')
                    skipped = True
                if re.search(r'\d+%\s+context left', text) or re.search(r'gpt-6\.1-sol\s+(?:medium|default)\s+·', text, re.I):
                    result = {'ready_ns': time.perf_counter_ns() - start, 'skipped_update': skipped}
                    os.write(master, b'HOST_TYPING_PROBE')
                    typing_start = time.monotonic()
                    while time.monotonic() - typing_start < 3:
                        if select.select([master], [], [], .05)[0]:
                            chunk = os.read(master, 65536)
                            data.extend(chunk)
                            if b'HOST_TYPING_PROBE' in ANSI.sub(b'', bytes(data[-10000:])):
                                result['typing_verified'] = True
                                break
                    break
        finally:
            raw.write_bytes(data)
            raw.chmod(0o600)
            try:
                os.killpg(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            _, status, usage = os.wait4(pid, 0)
            os.close(master)
        if result is None:
            raise RuntimeError('No readiness marker; inspect private PTY artifact: ' + str(raw))
        result.update(user_s=usage.ru_utime, system_s=usage.ru_stime,
                      minor_faults=usage.ru_minflt, major_faults=usage.ru_majflt,
                      max_rss_kib=usage.ru_maxrss)
        if not result.get('typing_verified'):
            raise RuntimeError('Readiness marker seen, but typing was not verified')
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-from', type=Path, default=Path.home() / '.codex')
    parser.add_argument('--resume', required=True)
    parser.add_argument('--repeat', type=int, default=3)
    parser.add_argument('--timeout', type=float, default=90)
    args = parser.parse_args()
    artifacts = ROOT / 'build/ci/time-accounting'
    artifacts.mkdir(parents=True, exist_ok=True)
    artifacts.chmod(0o700)
    results = []
    for index in range(args.repeat):
        result = run(args.state_from, args.resume, artifacts, index, args.timeout)
        results.append(result)
        (artifacts / 'linux-codex-baseline.json').write_text(json.dumps(results, indent=2) + '\n')
        print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
