"""Runs inside RetroOS, without any external serial control connection."""
import errno
import importlib.util
import json
import os
import stat
import subprocess
import sys
import time

spec = importlib.util.spec_from_file_location('bridge', '/86box_mcp.py')
bridge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bridge)
assert stat.S_ISCHR(os.stat('/dev/retroos-control').st_mode)
assert stat.S_IMODE(os.stat('/dev/retroos-control').st_mode) == 0o600
assert os.getuid() == 1001
assert os.stat('/dev/retroos-control').st_uid == os.getuid()
control = bridge.control_for(None, None)
assert isinstance(control, bridge.LocalControl), 'must automatically choose local transport'

def request(command):
    result = control.request(command)
    assert result['ok'], (command, result)
    return result

request('profile off')
assert request('status')['profile'] is False
request('profile reset')
assert request('profile syscalls')['syscalls'] == []
request('profile on')
assert request('status')['profile'] is True
for _ in range(100):
    os.stat('/dev/retroos-control')
request('profile off')
rows = request('profile syscalls')['syscalls']
assert rows and all(r['calls'] > 0 and 0 <= r['max_ns'] <= r['ns'] for r in rows)
assert request('profile totals')['elapsed_ns'] > 0
assert request('profile execution')['calls'] > 0
assert 'directory_scan' in request('profile io')['stages']
assert request('profile heap')['counters']
for name in ('profile reads', 'profile top', 'profile rm', 'screen'):
    result = control.request(name)
    assert 'error' not in result, (name, result)
assert control.request('invalid command')['ok'] is False
assert request('status')['profile'] is False

from profile_report import make_report
os.mkdir('/home/retroos/profile-test')
request('profile begin')
assert control.request('profile report')['ok'] is False, 'live snapshots must not look frozen'
start = time.monotonic_ns()
time.sleep(.08)
subprocess.run([sys.executable, '-c', 'sum(range(100000))'], check=True)
for _ in range(100):
    os.stat('/home/retroos/profile-test')
fd = os.open('/home/retroos/profile-test/new', os.O_CREAT | os.O_WRONLY, 0o600)
os.write(fd, b'profile data')
os.close(fd)
os.unlink('/home/retroos/profile-test/new')
os.stat('/home/retroos/profile-test')
elapsed = time.monotonic_ns() - start
packet = request('profile end')
capture = make_report(packet)
assert capture['quality']['valid'], capture['quality']
assert abs(capture['window']['elapsed_ns'] - elapsed) < 30_000_000, (capture['window'], elapsed)
categories = {row['category']: row['ns'] for row in capture['accounting']['categories']}
assert categories['idle'] >= 30_000_000, categories
assert categories['syscall_handlers'] > 0, categories
assert sum(categories.values()) >= capture['window']['elapsed_ns'] - capture['quality']['tolerance_ns']
assert capture['nested_io']['additive'] is False
directory_rows = capture['directory_cache']['rows']
assert sum(r['hits'] for r in directory_rows) > 0, directory_rows
assert sum(r['builds'] for r in directory_rows) > 0, directory_rows
assert sum(r['namespace_invalidations'] for r in directory_rows) > 0, directory_rows
assert request('profile report') == packet, 'reporting must not change frozen counters'
details = request('profile workers')
assert details == packet['raw']['workers']
assert details['scope'] == 'worker_cpu_time' and details['overlaps_bsp_wall_time'] is True
assert details['window_id'] == packet['window']['id']
for row in details['cpus']:
    assert row['cpu'] >= 2 and any(call['calls'] > 0 for call in row['syscalls'])
    assert all(call['ns'] >= call['max_ns'] for call in row['syscalls'])
workers = request('parallel status')
assert workers['scope'] == 'worker_syscalls_since_boot' and workers['bsp_included'] is False
assert workers['cpu_mask'] & 1 and not workers['cpu_mask'] & 2
for row in workers['cpus']:
    assert row['cpu'] >= 2 and workers['cpu_mask'] & (1 << row['cpu'])
    assert row['syscalls'] > 0 and row['handler_ns'] >= 0 and row['lock_wait_ns'] >= 0
if workers['cpu_mask'] != 1:
    assert workers['cpus'], 'the helper must execute kernel handlers on its worker CPU'
    assert details['cpus'], 'worker syscalls must be present in the recorded window'
time.sleep(.01)
assert request('profile report') == packet, 'stopped counters must not include collection time'
with open('/home/retroos/capture.json', 'w') as output:
    json.dump(capture, output)
request('profile reset')
empty = request('profile report')
assert empty['window']['elapsed_ns'] == 0
assert empty['raw']['execution']['calls'] == 0
assert empty['raw']['execution']['total'] == 0
assert empty['raw']['syscalls']['syscalls'] == []
assert empty['raw']['workers']['cpus'] == []
assert empty['directories']['total_paths'] == 0
request('profile begin')
time.sleep(.01)
second = make_report(request('profile end'))
assert second['window']['id'] != capture['window']['id']
assert second['quality']['valid'], second['quality']

# Independent opens, split commands, busy protection, fragmented large reads,
# and recovery after rejected writes. No character-device page caching/offsets.
a = os.open('/dev/retroos-control', os.O_RDWR | os.O_NONBLOCK)
b = os.open('/dev/retroos-control', os.O_RDWR | os.O_NONBLOCK)
try:
    try:
        os.read(a, 1)
        raise AssertionError('empty stream must return EAGAIN')
    except BlockingIOError:
        pass
    for data, error in ((b'x' * 257, errno.E2BIG), (b'status\nstatus\n', errno.EINVAL), (b'\xff\n', errno.EINVAL)):
        try:
            os.write(a, data)
            raise AssertionError('accepted invalid input')
        except OSError as e:
            assert e.errno == error, e
    assert os.write(a, b'profile ') == 8
    assert os.write(a, b'io\n') == 3
    os.write(b, b'status\n')
    try:
        os.write(a, b'status\n')
        raise AssertionError('overwrote unread response')
    except OSError as e:
        assert e.errno == errno.EBUSY, e
    def receive(fd):
        result = bytearray()
        for _ in range(5000):
            try:
                chunk = os.read(fd, 7)
            except BlockingIOError:
                time.sleep(.001)
                continue
            assert chunk
            result.extend(chunk)
            if result.endswith(b'\n'):
                return json.loads(result)
        raise AssertionError('reply timed out')
    assert 'stages' in receive(a)
    assert 'profile' in receive(b)
    # Closing a queued request must not leak a session or contaminate another.
    os.write(a, b'status\n')
finally:
    os.close(a)
    os.close(b)
control.close()
for _ in range(40):
    c = bridge.LocalControl()
    assert c.request('status')['ok']
    c.close()

# Exercise the actual stdio MCP server inside the guest, not just its client.
messages = [
    {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {}},
    {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'},
    *[{'jsonrpc': '2.0', 'id': i, 'method': 'tools/call', 'params': {'name': name, 'arguments': {}}}
      for i, name in enumerate(('diagnostics_status', 'profile_io', 'profile_totals', 'profile_heap',
                               'profile_begin', 'profile_end', 'profile_report'), 3)],
]
result = subprocess.run([sys.executable, '/86box_mcp.py'],
    input=''.join(json.dumps(m) + '\n' for m in messages), capture_output=True, text=True)
assert result.returncode == 0, result.stderr
replies = [json.loads(line) for line in result.stdout.splitlines()]
assert [r['id'] for r in replies] == list(range(1, 10)), replies
assert 'profile_io' in {t['name'] for t in replies[1]['result']['tools']}
for r in replies[2:]:
    assert r['result']['isError'] is False, r
    assert json.loads(r['result']['content'][0]['text'])['ok'], r
for r in replies[-2:]:
    assert json.loads(r['result']['content'][0]['text'])['quality']['valid'], r
print('LOCAL_CONTROL_PASS: kernel device and stdio MCP work without COM2', file=sys.stderr, flush=True)
