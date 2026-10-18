import importlib.util
from pathlib import Path
import tempfile
import unittest


spec = importlib.util.spec_from_file_location(
    'record_linux_wifi', Path(__file__).resolve().parents[1] / 'tools/record_linux_wifi.py')
recorder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recorder)


class ControlWriteTests(unittest.TestCase):
    def test_appends_without_truncating_existing_commands(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'control'
            path.write_text('existing\n')
            recorder.write_control(path, 'new\n')
            self.assertEqual(path.read_text(), 'existing\nnew\n')

    @unittest.skipUnless(Path('/proc/thread-self/comm').exists(), 'Linux procfs required')
    def test_supports_kernel_control_file_that_rejects_seek_end(self):
        # Like kprobe_events, this control file rejects SEEK_END with EINVAL.
        # Only this test thread's name changes; restore it before returning.
        path = Path('/proc/thread-self/comm')
        original = path.read_text()
        with self.assertRaises(OSError) as caught:
            with path.open('a'):
                pass
        self.assertEqual(caught.exception.errno, 22)
        try:
            recorder.write_control(path, 'wifi-probe-test\n')
            self.assertEqual(path.read_text(), 'wifi-probe-test\n')
        finally:
            recorder.write_control(path, original)


class GrubEntryTests(unittest.TestCase):
    def entry(self, options='quiet splash', prefix='/boot', indent=''):
        return '\n'.join(indent + row for row in [
            "menuentry 'Ubuntu' --id original {",
            '    search --fs-uuid --set=root existing-root',
            '    savedefault',
            f'    linux {prefix}/vmlinuz-7.0-test root=UUID=existing-root ro {options}',
            f'    initrd /intel-ucode.img {prefix}/initrd.img-7.0-test',
            '}', ''])

    def test_keeps_boot_settings_and_microcode(self):
        result = recorder.grub_entry(self.entry(), '7.0-test')
        self.assertIn('search --fs-uuid --set=root existing-root', result)
        self.assertIn('root=UUID=existing-root ro quiet splash', result)
        self.assertIn('/intel-ucode.img /boot/initrd.img-7.0-test-retroos-wifi-v2', result)
        self.assertNotIn('savedefault', result)
        self.assertIn('--id retroos-linux-wifi-capture', result)

    def test_skips_recovery_and_handles_submenu(self):
        config = self.entry(options='recovery') + "submenu 'Advanced' {\n"
        config += self.entry(prefix='', indent='\t') + '}\n'
        result = recorder.grub_entry(config, '7.0-test')
        self.assertIn('/initrd.img-7.0-test-retroos-wifi-v2', result)
        self.assertNotIn(' recovery', result)

    def test_rejects_wrong_kernel_or_missing_initrd(self):
        with self.assertRaises(RuntimeError):
            recorder.grub_entry(self.entry(), 'other-kernel')
        with self.assertRaises(RuntimeError):
            recorder.grub_entry(self.entry().replace('initrd.img-7.0-test', 'different.img'), '7.0-test')


if __name__ == '__main__':
    unittest.main()
