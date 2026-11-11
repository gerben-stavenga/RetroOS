#!/usr/bin/env python3
"""Measure shell output and completion through the installed exec-server RPC."""
import argparse
import base64
import json
import os
from pathlib import Path
import select
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary')
    parser.add_argument('--cwd', default='/tmp')
    args = parser.parse_args()
    origin = time.monotonic()

    def record(event, **fields):
        print(json.dumps(dict(event=event, elapsed=time.monotonic() - origin, **fields)), flush=True)

    for shell in ('/bin/sh', '/bin/bash'):
        for command in ('printf DIRECT_PASS', 'true', 'printf PIPE_PASS | /bin/cat'):
            start = time.monotonic()
            result = subprocess.run([shell, '-c', command], capture_output=True, timeout=20)
            assert result.returncode == 0, result.stderr
            record('direct', shell=shell, command=command, seconds=time.monotonic()-start)

    with open('/tmp/exec-probe-stderr', 'wb') as errors:
        process = subprocess.Popen([args.binary, '--listen', 'stdio'], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=errors, bufsize=0)
        pending = b''
        sequence = 0

        def receive(deadline):
            nonlocal pending
            while b'\n' not in pending:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([process.stdout], [], [], max(0, remaining))[0]:
                    raise TimeoutError('RPC output timeout')
                data = os.read(process.stdout.fileno(), 65536)
                if not data:
                    raise RuntimeError('exec-server closed stdout: ' + str(process.poll()))
                pending += data
            line, pending = pending.split(b'\n', 1)
            message = json.loads(line)
            record('message', message=message)
            return message

        def request(method, params):
            nonlocal sequence
            sequence += 1
            start = time.monotonic()
            process.stdin.write((json.dumps(dict(id=sequence, method=method, params=params))+'\n').encode())
            while True:
                message = receive(start+30)
                if message.get('id') == sequence:
                    assert 'error' not in message, message
                    record('rpc', method=method, seconds=time.monotonic()-start)
                    return message['result']

        try:
            request('initialize', dict(clientName='retroos-timing-probe'))
            process.stdin.write(b'{"method":"initialized"}\n')
            for index, (argv, expected) in enumerate([
                (['/bin/sh', '-c', 'printf RPC_PASS'], b'RPC_PASS'),
                (['/bin/bash', '-lc', 'printf LOGIN_PASS'], b'LOGIN_PASS'),
                (['/bin/sh', '-c', 'true'], b''),
                (['/bin/sh', '-c', 'printf PIPE_PASS | /bin/cat'], b'PIPE_PASS'),
                (['/bin/sh', '-c', 'printf DELAY_PASS; /bin/sleep 0.05'], b'DELAY_PASS'),
                (['/bin/sh', '-c', 'printf REPEAT_PASS'], b'REPEAT_PASS'),
            ]):
                identifier = 'probe-'+str(index)
                start = time.monotonic()
                record('start', process_id=identifier, argv=argv, tty=False)
                request('process/start', dict(processId=identifier, argv=argv,
                        cwd=Path(args.cwd).as_uri(), env={}, tty=False))
                after = 0
                output = b''
                while True:
                    result = request('process/read', dict(processId=identifier, waitMs=1000, afterSeq=after))
                    after = result.get('nextSeq', after+1)-1
                    output += b''.join(base64.b64decode(chunk['chunk']) for chunk in result.get('chunks', [])
                                       if chunk['stream'] == 'stdout')
                    record('read', process_id=identifier, result=result)
                    # Versions may return completion in the read reply instead of a notification.
                    if result.get('closed'):
                        break
                    if time.monotonic()-start > 20:
                        raise TimeoutError('command did not complete: '+identifier)
                assert result.get('exitCode') == 0, result
                assert output == expected, (output, expected)
                record('complete', process_id=identifier, seconds=time.monotonic()-start)
            record('PASS')
        finally:
            # EOF is the service's supported orderly shutdown. RetroOS's
            # kill syscall is currently a no-op, so SIGKILL cannot clean up
            # this fixture on the guest.
            process.stdin.close()
            process.wait(timeout=5)


if __name__ == '__main__':
    main()
