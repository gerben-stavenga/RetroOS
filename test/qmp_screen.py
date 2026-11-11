"""Read the terminal through QEMU's debugger without guest UART traffic."""
import json
import socket


class Screen:
    def __init__(self, path, control, output):
        self.socket = socket.socket(socket.AF_UNIX)
        self.socket.settimeout(20)
        self.socket.connect(str(path))
        self.stream = self.socket.makefile('rb')
        assert 'QMP' in json.loads(self.stream.readline())
        self.request('qmp_capabilities')
        self.layout = control.request('screen memory')
        self.output = output

    def request(self, command, arguments=None):
        message = {'execute': command}
        if arguments is not None:
            message['arguments'] = arguments
        self.socket.sendall(json.dumps(message).encode() + b'\n')
        while True:
            reply = json.loads(self.stream.readline())
            if 'error' in reply:
                raise RuntimeError(reply['error'])
            if 'return' in reply:
                return reply['return']

    def read(self):
        # All task address spaces share these static kernel mappings. memsave
        # uses QEMU's debugger and does not execute a guest diagnostic command.
        result = self.request('human-monitor-command', {'command-line':
            f'memsave {self.layout["address"]:#x} {self.layout["bytes"]} {json.dumps(str(self.output))}'})
        if result:
            raise RuntimeError(result)
        cells = self.output.read_bytes()[::2].decode('cp437')
        width = self.layout['width']
        return '\n'.join(cells[i:i + width] for i in range(0, len(cells), width)) + '\n'

    def close(self):
        self.stream.close()
        self.socket.close()
