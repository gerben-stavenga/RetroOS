"""Normalize one atomic, stopped kernel profile. Never sum nested I/O stages."""
ARCH_STAGES = ('policy_lookup', 'policy_install', 'bridge_in', 'ring0_enter_frame_in',
    'ring0_enter_dispatch', 'ring0_enter_frame_out', 'ring0_exit_frame_in',
    'ring0_exit_dispatch', 'ring0_exit_frame_out', 'decode', 'bridge_out')
IO_GROUPS = {
    'storage_device': ('disk_read', 'disk_write', 'disk_flush', 'volume_read', 'volume_flush'),
    'filesystem': ('ext4_read', 'ext4_create', 'ext4_set_meta', 'ext4_mkdir', 'ext4_commit_write',
        'ext4_unlink', 'ext4_rmdir', 'ext4_fsync', 'ext4_resize'),
    'namespace': ('directory_scan', 'path_resolve', 'write_permission', 'write_refresh'),
    'cache': ('cache_check', 'cache_miss', 'cache_insert'),
    'loader_and_mapping': ('read_allocate', 'read_fetch', 'read_copy', 'mmap_zero', 'mmap_read',
        'mmap_copy', 'elf_allocate', 'elf_read', 'elf_copy', 'elf_seek', 'vfs_lock', 'vfs_read'),
    'smb': ('smb_send', 'smb_receive', 'smb_sign', 'smb_verify', 'smb_response_allocate',
        'smb_read_decode', 'smb_encode'),
    'pipes': ('pipe_wait', 'pipe_allocate'),
    'event_loop': ('loop_writeback', 'loop_klog_sync', 'loop_deadlines', 'task_snapshot', 'loop_network', 'loop_prelude', 'alarm_arm'),
    'clock': ('rtc_read',),
}
SYSCALL_GROUPS = {
    'file_io': {'read', 'write', 'readv', 'writev', 'pread64', 'pwrite64', 'lseek', 'fsync',
        'fdatasync', 'sync', 'syncfs', 'sendfile', 'splice', 'copy_file_range'},
    'metadata_and_directory': {'stat', 'lstat', 'fstat', 'newfstatat', 'statx', 'getdents',
        'getdents64', 'access', 'faccessat', 'faccessat2', 'readlink', 'readlinkat', 'statfs', 'fstatfs'},
    'namespace_and_handles': {'open', 'openat', 'close', 'dup', 'dup2', 'dup3', 'fcntl', 'ioctl',
        'unlink', 'unlinkat', 'symlink', 'symlinkat', 'link', 'linkat', 'rename', 'renameat',
        'renameat2', 'mkdir', 'mkdirat', 'rmdir', 'chmod', 'fchmod', 'fchmodat', 'utimensat'},
    'memory': {'mmap', 'mmap2', 'munmap', 'mprotect', 'madvise', 'brk', 'msync', 'mremap'},
    'time_and_wait': {'clock_gettime', 'clock_gettime64', 'gettimeofday', 'time', 'nanosleep',
        'clock_nanosleep', 'futex', 'futex_time64', 'poll', 'ppoll', 'select', 'pselect6',
        'epoll_wait', 'epoll_pwait', 'sched_yield'},
    'process': {'clone', 'clone3', 'fork', 'vfork', 'execve', 'execveat', 'wait4', 'waitid',
        'exit', 'exit_group', 'getpid', 'gettid', 'getppid', 'prctl', 'arch_prctl', 'rseq'},
    'network': {'socket', 'socketpair', 'bind', 'listen', 'accept', 'accept4', 'connect',
        'sendto', 'recvfrom', 'sendmsg', 'recvmsg', 'getsockopt', 'setsockopt', 'shutdown'},
}


def make_report(packet):
    if not packet.get('ok'):
        return packet
    if packet.get('schema_version') != 1:
        raise ValueError('unsupported kernel profile schema')
    raw = packet['raw']
    window = packet['window']
    duration = window['elapsed_ns']
    checks = {}
    warnings = []
    tolerance = max(50_000, duration // 1000)
    checks['stopped'] = not window['running']
    checks['nonempty_window'] = duration > 0
    checks['window_duration_matches'] = window['stopped_ns'] - window['started_ns'] == duration
    checks['all_sections_ok'] = all(section.get('ok') for section in raw.values())
    checks['coarse_same_window'] = raw['totals']['elapsed_ns'] == duration
    conversion = packet['clock']['cycle_conversion']
    checks['calibrated_cycle_clock'] = bool(conversion and conversion['ns_per_cycle_fp32'] > 0)
    ns = (lambda cycles: cycles * conversion['ns_per_cycle_fp32'] >> 32) if checks['calibrated_cycle_clock'] else None
    syscall_rows = raw['syscalls']['syscalls']
    checks['syscall_counters_valid'] = all(r['calls'] > 0 and 0 <= r['max_ns'] <= r['ns'] for r in syscall_rows)
    checks['io_counters_valid'] = all(0 <= r['max_ns'] <= r['ns'] and (r['calls'] > 0 or r['ns'] == 0)
        for r in raw['io']['stages'].values())
    handlers = sum(r['ns'] for r in syscall_rows)
    categories = []
    errors = {}
    if ns:
        coarse = {key: ns(value) for key, value in raw['totals']['cycles'].items()}
        execution = raw['execution']
        guest = ns(execution['guest'])
        arch = ns(sum(execution[key] for key in ARCH_STAGES))
        writeback = raw['io']['stages']['loop_writeback']['ns']
        values = {
            'guest_execution_window': guest,
            'architecture_entry_exit': arch,
            'execution_wrapper_and_checks': coarse['guest_arch'] - guest - arch,
            'syscall_handlers': handlers,
            'deferred_dispatch_and_instrumentation': coarse['dispatch'] - handlers,
            'background_writeback': writeback,
            'other_outer_loop': coarse['loop'] - writeback,
            'scheduler_and_loop_control': coarse['scheduler'],
            **{key: coarse[key] for key in ('irq_drain', 'devices', 'audio',
                'display', 'input', 'serial_control', 'idle')},
        }
        errors['coarse_minus_wall_ns'] = sum(coarse.values()) - duration
        errors['architecture_minus_wall_ns'] = ns(execution['total']) - duration
        errors['ledger_minus_wall_ns'] = sum(values.values()) - duration
        checks['coarse_covers_window'] = abs(errors['coarse_minus_wall_ns']) <= tolerance
        checks['architecture_covers_window'] = abs(errors['architecture_minus_wall_ns']) <= tolerance
        checks['ledger_covers_window'] = abs(errors['ledger_minus_wall_ns']) <= tolerance
        # Do not clamp negative residuals or silently invent missing time.
        checks['nonnegative_categories'] = all(v >= 0 for v in values.values())
        categories = [{'category': key, 'ns': value, 'percent_of_window': 100 * value / duration if duration else None}
                      for key, value in values.items()]
    else:
        warnings.append('No independent cycle calibration: raw cycles and handler/I/O nanoseconds remain available; no combined nanosecond ledger was invented.')

    from syscall_names import NAMES
    names = NAMES
    rows = []
    for r in syscall_rows:
        name = names.get(r['abi'], {}).get(r['nr'], f"syscall_{r['abi']}_{r['nr']}")
        group = next((key for key, members in SYSCALL_GROUPS.items() if name in members), 'other')
        rows.append({**r, 'name': name, 'rubric': group,
            'average_ns': r['ns'] / r['calls'] if r['calls'] else None,
            'percent_of_handlers': 100 * r['ns'] / handlers if handlers else 0})
    rows.sort(key=lambda r: r['ns'], reverse=True)
    groups = {}
    for row in rows:
        group = groups.setdefault(row['rubric'], {'calls': 0, 'ns': 0})
        group['calls'] += row['calls']; group['ns'] += row['ns']
    nested = {}
    for name, stage in raw['io']['stages'].items():
        domain = next((key for key, members in IO_GROUPS.items() if name in members), 'other')
        nested.setdefault(domain, []).append({'stage': name, **stage,
            'average_ns': stage['ns'] / stage['calls'] if stage['calls'] else 0})
    for rows_in_group in nested.values():
        rows_in_group.sort(key=lambda row: row['ns'], reverse=True)
    worker_rows = []
    for cpu in raw.get('workers', {}).get('cpus', []):
        calls = []
        rubrics = {}
        for call in cpu['syscalls']:
            number = call['number']
            name = names.get(call['abi'], {}).get(number, f"syscall_{call['abi']}_{number}")
            rubric = next((key for key, members in SYSCALL_GROUPS.items() if name in members), 'other')
            calls.append({**call, 'name': name, 'rubric': rubric,
                'average_ns': call['ns'] / call['calls'] if call['calls'] else None})
            group = rubrics.setdefault(rubric, {'calls': 0, 'ns': 0})
            group['calls'] += call['calls']; group['ns'] += call['ns']
        io = {}
        for stage in cpu['io']:
            rubric = next((key for key, members in IO_GROUPS.items() if stage['stage'] in members), 'other')
            io.setdefault(rubric, []).append(stage)
        worker_rows.append({'cpu': cpu['cpu'], 'syscall_handler_ns': sum(c['ns'] for c in calls),
            'syscalls': {'rubrics': rubrics, 'rows': sorted(calls, key=lambda c: c['ns'], reverse=True)},
            'nested_io': {'additive': False, 'rubrics': io}})
    directories = packet['directories']
    directory_rows = [{**row, 'path': '/' + bytes.fromhex(row['path_hex']).decode('utf-8', errors='replace').lstrip('/')}
                      for row in directories['rows']]
    heap = {'additive': False, 'scope': 'shared_allocator_all_recording_callers',
        'meaning': 'allocator timings overlap execution; other cores may also contribute, so do not add them to the event-loop ledger'}
    for name, offset in (('allocation', 0), ('deallocation', 3)):
        calls, cycles, maximum = raw['heap']['counters'][offset:offset+3]
        heap[name] = {'calls': calls, 'cycles': cycles, 'max_cycles': maximum,
            'ns': ns(cycles) if ns else None, 'max_ns': ns(maximum) if ns else None,
            'average_ns': ns(cycles)/calls if ns and calls else None}
    if packet['event_table_overflow']:
        warnings.append('Legacy event-class table overflowed; syscall counters and the coarse ledger are independent of that bounded table.')
    warnings.extend([
        'This is elapsed time on the event-loop CPU, including blocking device work and parallel process coordination. Worker CPU execution is excluded; not Linux user/sys CPU accounting.',
        'Guest execution window includes IRQ/fault boundaries; nested fault counters must not be added again.',
        'The capture includes MCP bracketing and concurrent work, not an independently timed application interval.',
        'Instrumentation overhead is included, not estimated and subtracted. Compare a separate unprofiled run for observer overhead.',
        'I/O timings are inclusive, nested diagnostics. Neither rows nor rubric totals may be added to the execution ledger.',
    ])
    return {'ok': True, 'schema_version': 1, 'window': window, 'clock': packet['clock'],
        'accounting': {'unit': 'ns', 'disjoint': True, 'scope': 'bsp_wall_time',
            'worker_cpu_time_included': False, 'categories': categories,
            'active_ns': sum(r['ns'] for r in categories if r['category'] != 'idle') if ns else None,
            'syscall_handler_ns': handlers},
        'syscalls': {'unit': 'ns', 'meaning': 'synchronous handler time; excludes blocked sleep, deferred actions and architecture crossings',
            'rubrics': groups, 'rows': rows},
        'nested_io': {'unit': 'ns', 'additive': False, 'rubrics': nested},
        'workers': {'unit': 'ns', 'scope': 'worker_cpu_time', 'additive_to_wall_time': False,
            'meaning': 'per-core handler times overlap each other and the BSP ledger; nested I/O is inclusive',
            'cpus': worker_rows},
        'directory_cache': {'scope': 'directory-listing cache, including cached negative name lookups',
            'total_paths': directories['total_paths'], 'returned_paths': len(directory_rows),
            'omitted_paths': directories['total_paths'] - len(directory_rows), 'ranked_by': 'build_ns',
            'totals_including_omitted_paths': directories['totals'], 'rows': directory_rows},
        'block_cache': raw['block_cache']['cache'], 'heap': heap,
        'quality': {'valid': all(checks.values()), 'checks': checks, 'tolerance_ns': tolerance,
            'signed_alignment_errors_ns': errors, 'warnings': warnings}, 'raw': packet}
