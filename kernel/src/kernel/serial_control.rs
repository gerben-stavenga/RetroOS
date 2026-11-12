//! Kernel diagnostic control protocol on a dedicated serial port.
//!
//! COM1 may carry arbitrary log text, so control traffic gets its
//! own UART. The host sends one ASCII command per line and receives exactly
//! one JSON reply per line. No keyboard or OSD navigation is involved.

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use arch_abi::ComPort;
use crate::kernel::drivers::uart16550::{Uart16550, UartConfig};

pub(crate) mod local;
mod report;
static mut COMPOSITE_REPLY: bool = false;

// Only the cooperative event-loop owner serializes replies. A local command
// captures the same serializer's output instead of transmitting it on a UART.
struct LocalReply { bytes: alloc::vec::Vec<u8>, failed: bool }
static mut LOCAL_REPLY: Option<LocalReply> = None;

fn execute_local(machine: &mut impl crate::Arch, line: &[u8], stats: &mut super::startup::EventStats) -> (bool, alloc::vec::Vec<u8>) {
    unsafe { LOCAL_REPLY = Some(LocalReply { bytes: alloc::vec::Vec::new(), failed: false }); }
    let dump = execute(machine, line, stats);
    let reply = unsafe { (*core::ptr::addr_of_mut!(LOCAL_REPLY)).take().unwrap() };
    (dump, if reply.failed { b"{\"ok\":false,\"error\":\"reply too large or out of memory\"}\n".to_vec() } else { reply.bytes })
}

const RX_CAPACITY: usize = 256;
const RX_PER_POLL: usize = 64;
const INJECT_CAPACITY: usize = 512;
const TX_READY_POLLS: u32 = 100_000;

static LIVE: AtomicBool = AtomicBool::new(false);
static PORT: AtomicU8 = AtomicU8::new(0);
static RX_PENDING: AtomicBool = AtomicBool::new(false);
static mut RX: [u8; RX_CAPACITY] = [0; RX_CAPACITY];
static mut RX_LEN: usize = 0;
static mut DISCARDING: bool = false;
static mut INJECT: [u8; INJECT_CAPACITY] = [0; INJECT_CAPACITY];
static mut INJECT_HEAD: usize = 0;
static mut INJECT_TAIL: usize = 0;

fn uart() -> Option<Uart16550> {
    match PORT.load(Ordering::Relaxed) {
        1 => Some(Uart16550::new(ComPort::Com1)),
        2 => Some(Uart16550::new(ComPort::Com2)),
        _ => None,
    }
}

pub fn init<A: crate::Arch>(machine: &mut A, port: ComPort) -> bool {
    let endpoint = Uart16550::new(port);
    if !endpoint.is_present() { return false; }
    endpoint.initialize(UartConfig::UART_115200_8N1);
    endpoint.drain_rx();
    PORT.store(match port { ComPort::Com1 => 1, ComPort::Com2 => 2 }, Ordering::Relaxed);
    LIVE.store(true, Ordering::Relaxed);
    machine.route_isa_irq(endpoint.irq());
    endpoint.receive_interrupts(true);
    true
}

fn send(bytes: &[u8]) {
    let bytes = if unsafe { COMPOSITE_REPLY } { bytes.strip_suffix(b"\n").unwrap_or(bytes) } else { bytes };
    if let Some(reply) = unsafe { (*core::ptr::addr_of_mut!(LOCAL_REPLY)).as_mut() } {
        if !reply.failed {
            if bytes.len() > local::MAX_REPLY.saturating_sub(reply.bytes.len())
                || reply.bytes.try_reserve(bytes.len()).is_err() { reply.failed = true; }
            else { reply.bytes.extend_from_slice(bytes); }
        }
        return;
    }
    let Some(endpoint) = uart() else { return };
    for &byte in bytes {
        if endpoint.write_byte(TX_READY_POLLS, byte).is_err() {
            endpoint.receive_interrupts(false);
            LIVE.store(false, Ordering::Relaxed);
            return;
        }
    }
}

fn send_u64(mut value: u64) {
    let mut digits = [0u8; 20];
    let mut at = digits.len();
    loop {
        at -= 1;
        digits[at] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 { break; }
    }
    send(&digits[at..]);
}

fn ok() { send(b"{\"ok\":true}\n"); }

fn queued(count: usize) {
    send(b"{\"ok\":true,\"queued_scancodes\":");
    send_u64(count as u64);
    send(b"}\n");
}

fn status() {
    let snapshot = super::startup::profile_snapshot();
    send(b"{\"ok\":true,\"profile\":");
    send(if super::startup::profile_enabled() { b"true" } else { b"false" });
    send(b",\"trace\":");
    send(if super::startup::trace_enabled() { b"true" } else { b"false" });
    send(b",\"guest_permille\":");
    send_u64(snapshot.guest as u64);
    send(b",\"kernel_permille\":");
    send_u64(snapshot.kernel as u64);
    send(b",\"cycles\":");
    send_u64(snapshot.cycles);
    send(b"}\n");
}

fn read_profile() {
    send(b"{\"ok\":true,\"reads\":[");
    let mut first = true;
    super::event_profile::visit_dos_file_reads(|size, calls, cycles, max, fetch, copy| {
        if !first { send(b","); }
        first = false;
        send(b"{\"size\":");
        send_u64(u64::from(size));
        send(b",\"calls\":");
        send_u64(calls);
        send(b",\"cycles\":");
        send_u64(cycles);
        send(b",\"max\":");
        send_u64(max);
        send(b",\"fetch\":");
        send_u64(fetch);
        send(b",\"copy\":");
        send_u64(copy);
        send(b"}");
    });
    let [hits, misses, pages, inner_bytes] =
        super::block::cache::profile();
    send(b"],\"cache\":{\"hits\":");
    send_u64(hits);
    send(b",\"misses\":");
    send_u64(misses);
    send(b",\"pages\":");
    send_u64(pages);
    send(b",\"inner_bytes\":");
    send_u64(inner_bytes);
    send(b"}}\n");
}

fn syscall_profile() {
    send(b"{\"ok\":true,\"syscalls\":[");
    let mut first = true;
    super::event_profile::visit_syscalls(|abi, number, calls, ns, max| {
        if !first { send(b","); }
        first = false;
        send(b"{\"abi\":"); send_u64(u64::from(abi));
        send(b",\"nr\":"); send_u64(u64::from(number));
        send(b",\"calls\":"); send_u64(calls);
        send(b",\"ns\":"); send_u64(ns);
        send(b",\"max_ns\":"); send_u64(max);
        send(b"}");
    });
    send(b"]}\n");
}

fn top_profile() {
    send(b"{\"ok\":true,\"events\":[");
    let mut first = true;
    for (kind, key, cs, ip, calls, run, cycles, max) in super::event_profile::top(32) {
        if !first { send(b","); }
        first = false;
        send(b"{\"kind\":");
        send_u64(u64::from(kind));
        send(b",\"key\":");
        send_u64(u64::from(key));
        send(b",\"cs\":");
        send_u64(u64::from(cs));
        send(b",\"ip\":");
        send_u64(u64::from(ip));
        send(b",\"calls\":");
        send_u64(calls);
        send(b",\"run\":");
        send_u64(run);
        send(b",\"cycles\":");
        send_u64(cycles);
        send(b",\"max\":");
        send_u64(max);
        send(b"}");
    }
    send(b"]}\n");
}

fn rm_profile() {
    send(b"{\"ok\":true,\"targets\":[");
    let mut first = true;
    super::event_profile::visit_rm_targets(|kind, cs, ip, calls| {
        if !first { send(b","); }
        first = false;
        send(b"{\"kind\":");
        send_u64(u64::from(kind));
        send(b",\"cs\":");
        send_u64(u64::from(cs));
        send(b",\"ip\":");
        send_u64(u64::from(ip));
        send(b",\"calls\":");
        send_u64(calls);
        send(b"}");
    });
    let [calls, setup, dispatch, unwind] = super::event_profile::direct_rm_phases();
    send(b"],\"direct\":{\"calls\":");
    send_u64(calls);
    send(b",\"setup\":");
    send_u64(setup);
    send(b",\"dispatch\":");
    send_u64(dispatch);
    send(b",\"unwind\":");
    send_u64(unwind);
    send(b"}}\n");
}

fn execution_profile<A: crate::Arch>(machine: &A) {
    let p = machine.execution_profile();
    send(b"{\"ok\":true");
    for (name, cycles) in [
        (b"calls".as_slice(), p.calls),
        (b"total", p.total_cycles()),
        (b"ring1", p.ring1),
        (b"policy_lookup", p.policy_lookup),
        (b"policy_install", p.policy_install),
        (b"bridge_in", p.bridge_in),
        (b"ring0_enter_frame_in", p.ring0_enter_frame_in),
        (b"ring0_enter_dispatch", p.ring0_enter_dispatch),
        (b"ring0_enter_frame_out", p.ring0_enter_frame_out),
        (b"guest", p.guest),
        (b"ring0_exit_frame_in", p.ring0_exit_frame_in),
        (b"ring0_exit_dispatch", p.ring0_exit_dispatch),
        (b"ring0_exit_frame_out", p.ring0_exit_frame_out),
        (b"decode", p.decode),
        (b"bridge_out", p.bridge_out),
        (b"user_fault_calls", p.user_fault_calls),
        (b"user_fault_cycles", p.user_fault_cycles),
        (b"kernel_fault_calls", p.kernel_fault_calls),
        (b"kernel_fault_cycles", p.kernel_fault_cycles),
    ] {
        send(b",\"");
        send(name);
        send(b"\":");
        send_u64(cycles);
    }
    send(b",\"devices\":{");
    for (index, (name, [calls, cycles])) in super::event_profile::DEVICE_NAMES.into_iter()
        .zip(super::event_profile::device_entries()).enumerate() {
        if index != 0 { send(b","); }
        send(b"\""); send(name.as_bytes()); send(b"\":{\"calls\":");
        send_u64(calls); send(b",\"cycles\":"); send_u64(cycles); send(b"}");
    }
    send(b"},\"vga_instructions\":[");
    let mut first = true;
    for entry in super::event_profile::vga_instructions().into_iter().filter(|entry| entry.calls != 0) {
        if !first { send(b","); }
        first = false;
        send(b"{\"cs\":"); send_u64(u64::from(entry.cs));
        send(b",\"ip\":"); send_u64(u64::from(entry.ip));
        send(b",\"bytes\":"); send_u64(u64::from(entry.bytes));
        send(b",\"max_count\":"); send_u64(u64::from(entry.max_count));
        send(b",\"calls\":"); send_u64(entry.calls); send(b"}");
    }
    send(b"]}\n");
}

fn trim(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) { bytes = &bytes[1..]; }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) { bytes = &bytes[..bytes.len() - 1]; }
    bytes
}

fn injection_free() -> usize {
    unsafe {
        if INJECT_TAIL >= INJECT_HEAD {
            INJECT_CAPACITY - 1 - (INJECT_TAIL - INJECT_HEAD)
        } else {
            INJECT_HEAD - INJECT_TAIL - 1
        }
    }
}

fn inject(scancode: u8) {
    unsafe {
        INJECT[INJECT_TAIL] = scancode;
        INJECT_TAIL = (INJECT_TAIL + 1) % INJECT_CAPACITY;
    }
}

fn pop_injected() -> Option<u8> {
    unsafe {
        if INJECT_HEAD == INJECT_TAIL { return None; }
        let scancode = INJECT[INJECT_HEAD];
        INJECT_HEAD = (INJECT_HEAD + 1) % INJECT_CAPACITY;
        Some(scancode)
    }
}

fn queue_tap(scancode: u8, extended: bool) -> usize {
    if extended { inject(0xE0); }
    inject(scancode);
    if extended { inject(0xE0); }
    inject(scancode | 0x80);
    if extended { 4 } else { 2 }
}

fn named_key(name: &[u8]) -> Option<(u8, bool)> {
    let ordinary = [
        (b"esc".as_slice(), 0x01), (b"backspace", 0x0E), (b"tab", 0x0F),
        (b"enter", 0x1C), (b"space", 0x39), (b"f1", 0x3B), (b"f2", 0x3C),
        (b"f3", 0x3D), (b"f4", 0x3E), (b"f5", 0x3F), (b"f6", 0x40),
        (b"f7", 0x41), (b"f8", 0x42), (b"f9", 0x43), (b"f10", 0x44),
        (b"f11", 0x57), (b"f12", 0x58),
    ];
    for &(key, scancode) in &ordinary {
        if name.eq_ignore_ascii_case(key) { return Some((scancode, false)); }
    }
    let extended = [
        (b"home".as_slice(), 0x47), (b"up", 0x48), (b"pgup", 0x49),
        (b"left", 0x4B), (b"right", 0x4D), (b"end", 0x4F),
        (b"down", 0x50), (b"pgdn", 0x51), (b"insert", 0x52), (b"delete", 0x53),
    ];
    for &(key, scancode) in &extended {
        if name.eq_ignore_ascii_case(key) { return Some((scancode, true)); }
    }
    None
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_hex_pair(pair: &[u8]) -> Option<u8> {
    let high = hex_nibble(*pair.first()?)?;
    let low = hex_nibble(*pair.get(1)?)?;
    Some((high << 4) | low)
}

fn execute<A: crate::Arch>(machine: &mut A, line: &[u8], stats: &mut super::startup::EventStats) -> bool {
    let line = trim(line);
    stats.control_checkpoint(machine);
    if line.eq_ignore_ascii_case(b"profile begin") {
        machine.execution_profile_set(false);
        if super::startup::profile_enabled() { super::startup::reset_profile(); }
        else { super::startup::set_profile(true); }
        machine.execution_profile_reset();
        machine.execution_profile_set(true);
        stats.control_start(machine);
        send(b"{\"ok\":true,\"window_id\":"); send_u64(u64::from(super::startup::profile_generation()));
        send(b",\"started_ns\":"); send_u64(super::startup::profile_totals().started_ns); send(b"}\n");
    } else if line.eq_ignore_ascii_case(b"profile end") {
        machine.execution_profile_set(false);
        stats.control_stop(machine);
        super::startup::set_profile(false);
        report::write(machine, stats);
    } else if line.eq_ignore_ascii_case(b"profile report") {
        if super::startup::profile_enabled() {
            send(b"{\"ok\":false,\"error\":\"stop recording with profile end before reading a frozen report\"}\n");
        } else { report::write(machine, stats); }
    } else if line.eq_ignore_ascii_case(b"profile on") {
        if !super::startup::profile_enabled() {
            super::startup::set_profile(true);
            machine.execution_profile_set(true);
            stats.control_start(machine);
        }
        ok();
    } else if line.eq_ignore_ascii_case(b"profile off") {
        machine.execution_profile_set(false);
        stats.control_stop(machine);
        super::startup::set_profile(false);
        ok();
    } else if line.eq_ignore_ascii_case(b"profile reset") {
        let enabled = super::startup::profile_enabled();
        machine.execution_profile_reset();
        super::startup::reset_profile();
        if enabled { stats.control_start(machine); }
        ok();
    } else if line.eq_ignore_ascii_case(b"profile dump") {
        super::startup::print_profile();
        status();
    } else if line.eq_ignore_ascii_case(b"profile reads") {
        read_profile();
    } else if line.eq_ignore_ascii_case(b"profile io") {
        send(b"{\"ok\":true,\"stages\":{");
        for (index, ((name, [calls, bytes, ns]), maximum)) in super::event_profile::FILE_IO_NAMES.into_iter()
            .zip(super::event_profile::file_io()).zip(super::event_profile::file_io_max()).enumerate() {
            if index != 0 { send(b","); }
            send(b"\""); send(name.as_bytes()); send(b"\":{\"calls\":"); send_u64(calls);
            send(b",\"bytes\":"); send_u64(bytes); send(b",\"ns\":"); send_u64(ns);
            send(b",\"max_ns\":"); send_u64(maximum); send(b"}");
        }
        send(b"}}\n");
    } else if line.eq_ignore_ascii_case(b"profile heap") {
        send(b"{\"ok\":true,\"counters\":[");
        for (i, value) in lib::heap::profile().into_iter().enumerate() {
            if i != 0 { send(b","); }
            send_u64(value);
        }
        send(b"]}\n");
    } else if line.eq_ignore_ascii_case(b"profile syscalls") {
        syscall_profile();
    } else if line.eq_ignore_ascii_case(b"profile top") {
        top_profile();
    } else if line.eq_ignore_ascii_case(b"profile rm") {
        rm_profile();
    } else if line.eq_ignore_ascii_case(b"profile execution") {
        execution_profile(machine);
    } else if line.eq_ignore_ascii_case(b"profile totals") {
        let totals = super::startup::profile_totals();
        send(b"{\"ok\":true,\"elapsed_ns\":"); send_u64(totals.elapsed_ns);
        send(b",\"cycles\":{");
        for (index, (name, cycles)) in super::startup::PROFILE_TOTAL_NAMES.into_iter().zip(totals.cycles).enumerate() {
            if index != 0 { send(b","); }
            send(b"\""); send(name.as_bytes()); send(b"\":"); send_u64(cycles);
        }
        send(b"}}\n");
    } else if line.eq_ignore_ascii_case(b"trace process") {
        super::startup::set_process_trace();
        ok();
    } else if line.eq_ignore_ascii_case(b"trace fs") {
        super::startup::set_filesystem_trace();
        ok();
    } else if line.eq_ignore_ascii_case(b"trace on") {
        super::startup::set_trace(true);
        ok();
    } else if line.eq_ignore_ascii_case(b"trace off") {
        super::startup::set_trace(false);
        ok();
    } else if line.eq_ignore_ascii_case(b"status") {
        status();
    } else if line.eq_ignore_ascii_case(b"screen memory") {
        // A debugger can sample this stable kernel-owned projection without
        // making the guest transmit 4 KiB of hex through a polling UART.
        let cells = lib::term::term().cells();
        send(b"{\"ok\":true,\"address\":");
        send_u64(cells.as_ptr() as usize as u64);
        send(b",\"bytes\":4000,\"width\":80,\"height\":25}\n");
    } else if line.eq_ignore_ascii_case(b"screen") {
        // Hex UTF-8 keeps arbitrary terminal cells out of the JSON syntax.
        // The grid is the same source used by VGA and framebuffer renderers.
        const HEX: &[u8; 16] = b"0123456789abcdef";
        send(b"{\"width\":80,\"height\":25,\"texthex\":\"");
        for row in lib::term::term().unicode_cells().chunks(80) {
            for cell in row {
                let mut utf8 = [0; 4];
                for byte in cell.character.encode_utf8(&mut utf8).bytes() {
                    send(&[HEX[(byte >> 4) as usize], HEX[(byte & 15) as usize]]);
                }
            }
            send(b"0a");
        }
        send(b"\"}\n");
    } else if line.eq_ignore_ascii_case(b"debug dump") {
        ok();
        return true;
    } else if let Some(name) = line.strip_prefix(b"key ") {
        if let Some((scancode, extended)) = named_key(trim(name)) {
            let count = if extended { 4 } else { 2 };
            if injection_free() >= count {
                queued(queue_tap(scancode, extended));
            } else {
                send(b"{\"ok\":false,\"error\":\"key queue full\"}\n");
            }
        } else {
            send(b"{\"ok\":false,\"error\":\"unknown key\"}\n");
        }
    } else if let Some(encoded) = line.strip_prefix(b"texthex ") {
        if encoded.is_empty() || encoded.len() % 2 != 0 {
            send(b"{\"ok\":false,\"error\":\"invalid text encoding\"}\n");
            return false;
        }
        let mut count = 0;
        for pair in encoded.chunks_exact(2) {
            let Some(byte) = decode_hex_pair(pair) else {
                send(b"{\"ok\":false,\"error\":\"invalid text encoding\"}\n");
                return false;
            };
            let length = super::keyboard::ascii_to_scancodes(byte).1;
            if length == 0 {
                send(b"{\"ok\":false,\"error\":\"invalid text encoding\"}\n");
                return false;
            }
            count += length;
        }
        if injection_free() < count {
            send(b"{\"ok\":false,\"error\":\"key queue full\"}\n");
            return false;
        }
        for pair in encoded.chunks_exact(2) {
            let Some(byte) = decode_hex_pair(pair) else {
                send(b"{\"ok\":false,\"error\":\"invalid text encoding\"}\n");
                return false;
            };
            let (sequence, length) = super::keyboard::ascii_to_scancodes(byte);
            for &scancode in &sequence[..length] {
                inject(scancode);
            }
        }
        queued(count);
    } else {
        send(b"{\"ok\":false,\"error\":\"unknown command\"}\n");
    }
    false
}

/// Drain a bounded amount of RX work before returning to the guest. `true`
/// asks the event-loop owner to dump its current register/personality state.
pub(super) fn poll<A: crate::Arch>(machine: &mut A, events: &mut alloc::vec::Vec<crate::Irq>, tick: bool, stats: &mut super::startup::EventStats) -> bool {
    let mut dump = local::poll(machine, stats);
    // Local clients can inject keys without a physical diagnostic UART.
    if tick && let Some(scancode) = pop_injected() { events.push(crate::Irq::Key(scancode)); }
    if !LIVE.load(Ordering::Relaxed) { return dump; }
    let Some(endpoint) = uart() else { return dump };
    // Consume our physical UART IRQ instead of forwarding it to the guest.
    // An idle diagnostic channel must not cause a port-I/O VM exit every ms.
    let irq = take_irq(events, endpoint.irq());
    let receive = irq || RX_PENDING.load(Ordering::Relaxed);
    let mut pending = receive;
    for _ in 0..if receive { RX_PER_POLL } else { 0 } {
        let Ok(byte) = endpoint.read_byte(1) else { pending = false; break };
        unsafe {
            if byte == b'\n' || byte == b'\r' {
                if DISCARDING {
                    DISCARDING = false;
                    RX_LEN = 0;
                    send(b"{\"ok\":false,\"error\":\"command too long\"}\n");
                } else if RX_LEN != 0 {
                    let len = RX_LEN;
                    RX_LEN = 0;
                    dump |= execute(machine, &RX[..len], stats);
                }
            } else if !DISCARDING {
                if RX_LEN == RX_CAPACITY {
                    DISCARDING = true;
                    RX_LEN = 0;
                } else {
                    RX[RX_LEN] = byte;
                    RX_LEN += 1;
                }
            }
        }
    }
    RX_PENDING.store(pending, Ordering::Relaxed);
    if receive { machine.rearm_irq(endpoint.irq()); }
    dump
}

fn take_irq(events: &mut alloc::vec::Vec<crate::Irq>, line: u8) -> bool {
    let mut pending = false;
    events.retain(|event| {
        if matches!(event, crate::Irq::Hw(irq) if *irq == line) {
            pending = true;
            false
        } else { true }
    });
    pending
}

#[cfg(test)]
mod tests {
    use super::{take_irq, trim};

    #[test]
    fn uart_irq_is_consumed_without_disturbing_other_events() {
        use crate::Irq;
        let mut events = alloc::vec![Irq::Hw(0), Irq::Hw(3), Irq::Key(0x1e), Irq::Hw(4), Irq::Hw(3)];
        assert!(take_irq(&mut events, 3));
        assert!(matches!(events.as_slice(), [Irq::Hw(0), Irq::Key(0x1e), Irq::Hw(4)]));
        assert!(!take_irq(&mut events, 3));
        assert_eq!(events.len(), 3);
    }

    #[test]
    fn command_whitespace_is_not_semantic() {
        assert_eq!(trim(b"  profile on\r "), b"profile on");
    }
}

/// Injected keyboard bytes have their own serial cadence; RX is IRQ-driven.
pub(crate) fn next_deadline(now: u64) -> Option<u64> {
    if local::pending() { return Some(now); }
    if RX_PENDING.load(Ordering::Relaxed) { return Some(now); }
    unsafe { (INJECT_HEAD != INJECT_TAIL).then(|| now.saturating_add(1_000_000)) }
}
