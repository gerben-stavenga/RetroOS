#!/usr/bin/env python3
"""The conformance runner must never turn an unexecuted suite into a pass."""
import unittest
from unittest.mock import patch
from windows_conformance import observe, import_audit


class Results(unittest.TestCase):
    def test_loader_failure_is_not_a_timeout_or_assertion_failure(self):
        log = 'Windows: unresolved USER32.dll!Missing\n!!! FATAL !!!\n'
        result = observe(log, -15, False)
        self.assertEqual(result['status'], 'loader-blocked')
        self.assertEqual(result['summaries'], [])
        self.assertEqual(result['diagnostics'], ['Windows: unresolved USER32.dll!Missing'])

    def test_success_requires_summary_and_guest_exit(self):
        summary = 'text: 197 tests executed (0 marked as todo, 0 failures), 2 skipped.\n'
        self.assertEqual(observe(summary, 0, False)['status'], 'incomplete')
        self.assertEqual(observe('[mem] exit tid=1 code=0\n', 0, False)['status'], 'no-summary')
        result = observe(summary + '[mem] exit tid=1 code=0\n', 0, False)
        self.assertEqual(result['status'], 'passed')
        self.assertEqual(result['summaries'][0]['checks'], 197)
        self.assertEqual(result['summaries'][0]['skipped'], 2)

    def test_failure_counts_and_locations_are_preserved(self):
        log = ('win.c:123: Test failed: address 0x123\n'
               'win.c:123: Test failed: address 0x456\n'
               'win: 8 tests executed (0 marked as todo, 2 failures), 0 skipped.\n'
               '[mem] exit tid=1 code=2\n')
        result = observe(log, 0, False)
        self.assertEqual(result['status'], 'failed')
        self.assertEqual(result['checks_by_location'], {'win.c:123: Test failed': 2})

    def test_crash_after_child_summary_does_not_pass(self):
        log = ('msg: 2 tests executed (0 marked as todo, 0 failures), 0 skipped.\n'
               '[mem] exit tid=2 code=0\n!!! KERNEL PANIC !!!\n')
        self.assertEqual(observe(log, -15, False)['status'], 'crash')

    def test_timeout_after_partial_summary_does_not_pass(self):
        log = ('msg: 2 tests executed (0 marked as todo, 0 failures), 0 skipped.\n'
               '[mem] exit tid=2 code=0\n')
        self.assertEqual(observe(log, -15, True)['status'], 'timeout')

    def test_import_inventory_excludes_descriptor_rows_and_known_gates(self):
        output = """
 DLL Name: USER32.dll
 vma: Hint/Ord Member-Name Bound-To
 f430 108 KnownExport
 f446 120 KnownGate
 f458 121 Missing
 0000f028 0000f0c0 00000000 00000000 0000f7a0 0000f1c8
The Function Table
"""
        with patch('windows_conformance.command', return_value=output):
            self.assertEqual(import_audit('test.exe', {'user32': {'knownexport'}},
                                          {('user32', 'knowngate')}), ['USER32.DLL!Missing'])

    def test_bound_imports_are_audited(self):
        with patch('windows_conformance.command',return_value="DLL Name: KERNEL32.dll\n 4522 616 OutputDebugStringA 77e9bd34\n"):
            self.assertEqual(import_audit('test.exe',{},set()),['KERNEL32.DLL!OutputDebugStringA'])

    def test_singular_failure_summary(self):
        result=observe('dce: 136 tests executed (0 marked as todo, 1 failure), 0 skipped.\n[mem] exit tid=1 code=1\n',0,False)
        self.assertEqual(result['status'],'failed')
        self.assertEqual(result['summaries'][0]['failures'],1)

    def test_host_failure_is_not_guest_success(self):
        log = ('class: 4 tests executed (0 marked as todo, 0 failures), 0 skipped.\n'
               '[mem] exit tid=1 code=0\n')
        self.assertEqual(observe(log, 1, False)['status'], 'host-error')


if __name__ == '__main__':
    unittest.main()
