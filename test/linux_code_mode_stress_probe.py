#!/usr/bin/env python3
"""Drive repeated native code-mode sessions with live protocol framing."""
import argparse
import json
import os
import select
import struct
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary')
    parser.add_argument('--sessions', type=int, default=24)
    parser.add_argument('--start-delay', type=float, default=0)
    parser.add_argument('--after-command', nargs=argparse.REMAINDER,
                        help='Run a probe while all code-mode sessions remain resident')
    args = parser.parse_args()
    origin = time.monotonic()
    with open('/home/retroos/output-host' if os.path.isdir('/home/retroos') else '/tmp/retroos-code-host.stderr', 'wb') as errors:
        process = subprocess.Popen([args.binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors, bufsize=0)
        pending = b''

        def send(message):
            data = json.dumps(message).encode()
            process.stdin.write(struct.pack('<I', len(data))+data)

        def receive():
            nonlocal pending
            deadline = time.monotonic()+30
            while len(pending) < 4 or len(pending) < 4+struct.unpack('<I', pending[:4])[0]:
                remaining = deadline-time.monotonic()
                if remaining <= 0 or not select.select([process.stdout], [], [], max(0, remaining))[0]:
                    raise TimeoutError('code-mode protocol timeout')
                data = os.read(process.stdout.fileno(), 65536)
                if not data: raise RuntimeError('code-mode stdout closed: '+str(process.poll()))
                pending += data
            length = struct.unpack('<I', pending[:4])[0]
            message = json.loads(pending[4:4+length]); pending = pending[4+length:]
            print(json.dumps(dict(elapsed=time.monotonic()-origin, message=message)), flush=True)
            return message

        try:
            send(dict(type='connection/hello', supportedVersions=[1], requiredCapabilities=[], optionalCapabilities=[]))
            receive()
            time.sleep(args.start_delay)
            for index in range(args.sessions):
                session = 'probe'+str(index)
                send(dict(type='operation/request', id=2*index+1, request=dict(method='session/open', sessionId=session)))
                while True:
                    opened = receive()
                    if opened.get('type') == 'operation/response' and opened.get('id') == 2*index+1:
                        assert opened['result']['status'] == 'ok', opened
                        break
                marker = 'STRESS_PASS_'+str(index)
                source = "const a = Array.from({length: 10000}, (_, i) => ({i, x: String(i)})); await Promise.resolve(); text("+json.dumps(marker)+")"
                send(dict(type='operation/request', id=2*index+2, request=dict(method='session/execute', sessionId=session,
                    request=dict(tool_call_id=session, enabled_tools=[], source=source, yield_time_ms=1000, max_output_tokens=100))))
                while True:
                    result = receive()
                    if result.get('type') == 'execute/initialResponse':
                        value = result['result']
                        assert value['status'] == 'ok', result
                        value = value['value']['Result']
                        assert value.get('error_text') is None, result
                        assert any(item.get('text') == marker for item in value['content_items']), result
                        break
            print('CODE_MODE_STRESS_PASS', flush=True)
            if args.after_command:
                subprocess.run(args.after_command, check=True)
        finally:
            process.stdin.close()
            process.wait(timeout=10)


if __name__ == '__main__': main()
