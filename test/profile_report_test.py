"""Reconciliation must reject missing/overlapping/uncalibrated accounting."""
import copy
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from profile_report import ARCH_STAGES, make_report


def packet():
    # A 100 ms window, including nested disk work which must not be added.
    ms = 1_000_000
    cycles = dict(guest_arch=55, dispatch=20, loop=10, scheduler=5, irq_drain=2,
        devices=2, audio=1, display=1, input=1, serial_control=1, idle=2)
    execution = {'ok': True, 'calls': 10, 'guest': 40*ms, 'ring1': 50*ms, 'total': 100*ms,
        **dict.fromkeys(ARCH_STAGES, 0)}
    execution['policy_lookup'] = 10*ms
    return {'ok': True, 'schema_version': 1,
        'window': {'id': 1, 'running': False, 'started_ns': 10*ms, 'stopped_ns': 110*ms, 'elapsed_ns': 100*ms},
        'clock': {'cycle_conversion': {'ns_per_cycle_fp32': 1 << 32}},
        'raw': {
            'totals': {'ok': True, 'elapsed_ns': 100*ms, 'cycles': {k:v*ms for k,v in cycles.items()}},
            'execution': execution,
            'syscalls': {'ok': True, 'syscalls': [{'abi': 64, 'nr': 1, 'calls': 3, 'ns': 12*ms, 'max_ns': 6*ms}]},
            'io': {'ok': True, 'stages': {
                'loop_writeback': {'calls': 1, 'ns': 4*ms, 'max_ns': 4*ms, 'bytes': 0},
                'disk_flush': {'calls': 2, 'ns': 3*ms, 'max_ns': 2*ms, 'bytes': 0}}},
            'heap': {'ok': True, 'counters': [2, 8*ms, 5*ms, 1, ms, ms]},
            'block_cache': {'ok': True, 'cache': {'hits': 3, 'misses': 1}},
        },
        'directories': {'total_paths': 2, 'totals': {'builds': 2}, 'rows': [
            {'path_hex': b'usr/lib'.hex(), 'build_ns': 3*ms, 'builds': 1}]},
        'event_table_overflow': 0}


class ReportTests(unittest.TestCase):
    def test_nested_work_is_not_added_and_units_are_explicit(self):
        r = make_report(packet())
        self.assertTrue(r['quality']['valid'], r['quality'])
        self.assertEqual(sum(row['ns'] for row in r['accounting']['categories']), 100_000_000)
        self.assertEqual(r['accounting']['active_ns'], 98_000_000)
        self.assertFalse(r['nested_io']['additive'])
        self.assertFalse(r['heap']['additive'])
        self.assertEqual(r['heap']['allocation']['ns'], 8_000_000)
        self.assertEqual(r['syscalls']['rows'][0]['average_ns'], 4_000_000)
        self.assertEqual(r['syscalls']['rows'][0]['name'], 'write')
        self.assertEqual(r['syscalls']['rows'][0]['rubric'], 'file_io')
        self.assertEqual(r['directory_cache']['omitted_paths'], 1)
        self.assertEqual(r['directory_cache']['rows'][0]['path'], '/usr/lib')

    def test_worker_cpu_time_has_rubrics_without_changing_wall_accounting(self):
        p = packet()
        p['raw']['workers'] = {'ok': True, 'cpus': [{'cpu': 3,
            'syscalls': [{'abi': 64, 'number': 1, 'calls': 2, 'ns': 150_000_000, 'max_ns': 100_000_000}],
            'io': [{'stage': 'disk_read', 'calls': 1, 'ns': 90_000_000, 'max_ns': 90_000_000, 'bytes': 4096}]}]}
        r = make_report(p)
        self.assertTrue(r['quality']['valid'], r['quality'])
        self.assertEqual(sum(row['ns'] for row in r['accounting']['categories']), 100_000_000)
        self.assertFalse(r['workers']['additive_to_wall_time'])
        worker = r['workers']['cpus'][0]
        self.assertEqual(worker['cpu'], 3)
        self.assertEqual(worker['syscall_handler_ns'], 150_000_000)
        self.assertEqual(worker['syscalls']['rubrics']['file_io']['ns'], 150_000_000)
        self.assertEqual(worker['syscalls']['rows'][0]['name'], 'write')
        self.assertFalse(worker['nested_io']['additive'])
        self.assertEqual(worker['nested_io']['rubrics']['storage_device'][0]['bytes'], 4096)

    def test_negative_residual_is_visible_and_invalid(self):
        p = packet(); p['raw']['syscalls']['syscalls'][0]['ns'] = 30_000_000
        r = make_report(p)
        self.assertFalse(r['quality']['valid'])
        self.assertFalse(r['quality']['checks']['nonnegative_categories'])
        self.assertLess(next(row['ns'] for row in r['accounting']['categories']
            if row['category'] == 'deferred_dispatch_and_instrumentation'), 0)

    def test_missing_time_and_bad_clock_are_not_hidden(self):
        p = packet(); p['raw']['totals']['cycles']['scheduler'] += 10_000_000
        r = make_report(p)
        self.assertFalse(r['quality']['valid'])
        self.assertEqual(r['quality']['signed_alignment_errors_ns']['coarse_minus_wall_ns'], 10_000_000)
        p = packet(); p['clock']['cycle_conversion'] = None
        r = make_report(p)
        self.assertFalse(r['quality']['valid'])
        self.assertEqual(r['accounting']['categories'], [])
        self.assertIsNone(r['accounting']['active_ns'])
        self.assertEqual(r['accounting']['syscall_handler_ns'], 12_000_000)

    def test_live_or_mismatched_or_corrupt_counters_are_rejected(self):
        for mutation in ('live', 'generation', 'max', 'architecture'):
            p = copy.deepcopy(packet())
            if mutation == 'live': p['window']['running'] = True
            elif mutation == 'generation': p['raw']['totals']['elapsed_ns'] += 1
            elif mutation == 'max': p['raw']['syscalls']['syscalls'][0]['max_ns'] = 99_000_000
            else: p['raw']['execution']['total'] += 50_000_000
            self.assertFalse(make_report(p)['quality']['valid'], mutation)


if __name__ == '__main__': unittest.main()
