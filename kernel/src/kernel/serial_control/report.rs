//! One frozen packet: every layer belongs to the same stopped profile window.
use super::{send, send_u64};

pub(super) fn write(machine: &mut impl crate::Arch, stats: &mut crate::kernel::startup::EventStats) {
    let totals = crate::kernel::startup::profile_totals();
    unsafe { super::COMPOSITE_REPLY = true; }
    send(b"{\"ok\":true,\"schema_version\":1,\"window\":{\"id\":");
    send_u64(u64::from(crate::kernel::startup::profile_generation()));
    send(b",\"running\":false,\"scope\":\"event_loop_cpu_all_processes\",\"started_ns\":"); send_u64(totals.started_ns);
    send(b",\"stopped_ns\":"); send_u64(totals.stopped_ns);
    send(b",\"elapsed_ns\":"); send_u64(totals.elapsed_ns);
    send(b"},\"clock\":{\"time_unit\":\"nanoseconds\",\"cycle_conversion\":");
    if let Some((_, multiplier)) = machine.user_tsc_clock() {
        send(b"{\"source\":\"stable_tsc\",\"ns_per_cycle_fp32\":"); send_u64(multiplier); send(b"}");
    } else { send(b"null"); }
    send(b"},\"raw\":{");
    for (index, (name, command)) in [
        (b"totals".as_slice(), b"profile totals".as_slice()),
        (b"execution", b"profile execution"),
        (b"syscalls", b"profile syscalls"),
        (b"io", b"profile io"),
        (b"heap", b"profile heap"),
        (b"block_cache", b"profile reads"),
    ].into_iter().enumerate() {
        if index != 0 { send(b","); }
        send(b"\""); send(name); send(b"\":");
        super::execute(machine, command, stats);
    }
    send(b"},\"directories\":{\"total_paths\":");
    send_u64(crate::kernel::event_profile::directory_count() as u64);
    send(b",\"totals\":{");
    for (index, (name, value)) in crate::kernel::event_profile::DIRECTORY_FIELDS.into_iter()
        .zip(crate::kernel::event_profile::directory_totals()).enumerate() {
        if index != 0 { send(b","); }
        send(b"\""); send(name.as_bytes()); send(b"\":"); send_u64(value);
    }
    send(b"},\"limit\":64,\"rows\":[");
    for (index, (path, values)) in crate::kernel::event_profile::directories_top(64).into_iter().enumerate() {
        if index != 0 { send(b","); }
        send(b"{\"path_hex\":\"");
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in path { send(&[HEX[(byte >> 4) as usize], HEX[(byte & 15) as usize]]); }
        send(b"\"");
        for (name, value) in crate::kernel::event_profile::DIRECTORY_FIELDS.into_iter().zip(values) {
            send(b",\""); send(name.as_bytes()); send(b"\":"); send_u64(value);
        }
        send(b"}");
    }
    send(b"]},\"event_table_overflow\":"); send_u64(crate::kernel::event_profile::overflow());
    send(b"}");
    unsafe { super::COMPOSITE_REPLY = false; }
    send(b"\n");
}
