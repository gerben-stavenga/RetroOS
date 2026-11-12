//! Per-open command/reply streams for /dev/retroos-control. VFS callbacks only
//! queue bytes; the event-loop owner executes commands outside the VFS lock.
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

const FIRST_HANDLE: u64 = 4;
const MAX_CLIENTS: usize = 16;
pub(super) const MAX_REPLY: usize = 256 * 1024;
static PENDING: AtomicBool = AtomicBool::new(false);
static CLIENTS: spin::Mutex<Clients> = spin::Mutex::new(Clients { next: FIRST_HANDLE, entries: Vec::new() });

struct Clients { next: u64, entries: Vec<Client> }
struct Client {
    handle: u64,
    input: Vec<u8>,
    busy: bool,
    queued: bool,
    output: Vec<u8>,
    read: usize,
}

pub(crate) fn open() -> Option<u64> {
    let mut clients = CLIENTS.lock();
    if clients.entries.len() >= MAX_CLIENTS { return None; }
    let handle = clients.next;
    clients.next = handle.checked_add(1)?;
    clients.entries.try_reserve(1).ok()?;
    clients.entries.push(Client { handle, input: Vec::new(), busy: false, queued: false, output: Vec::new(), read: 0 });
    Some(handle)
}

pub(crate) fn close(handle: u64) -> i32 {
    let mut clients = CLIENTS.lock();
    let Some(index) = clients.entries.iter().position(|c| c.handle == handle) else { return -9; };
    clients.entries.swap_remove(index);
    0
}

pub(crate) fn write(handle: u64, bytes: &[u8]) -> i32 {
    let mut clients = CLIENTS.lock();
    let Some(client) = clients.entries.iter_mut().find(|c| c.handle == handle) else { return -9; };
    if bytes.is_empty() { return 0; }
    if client.busy || client.read < client.output.len() { return -16; }
    if !bytes.is_ascii() || bytes[..bytes.len()-1].contains(&b'\n') { return -22; }
    if bytes.len() > super::RX_CAPACITY.saturating_sub(client.input.len()) { return -7; }
    if client.input.try_reserve(bytes.len()).is_err() { return -12; }
    client.input.extend_from_slice(bytes);
    if bytes.ends_with(b"\n") {
        client.busy = true;
        client.queued = true;
        PENDING.store(true, Ordering::Release);
    }
    bytes.len() as i32
}

pub(crate) fn read(handle: u64, bytes: &mut [u8]) -> i32 {
    let mut clients = CLIENTS.lock();
    let Some(client) = clients.entries.iter_mut().find(|c| c.handle == handle) else { return -9; };
    if bytes.is_empty() { return 0; }
    if client.read == client.output.len() { return -11; }
    let n = bytes.len().min(client.output.len() - client.read);
    bytes[..n].copy_from_slice(&client.output[client.read..client.read+n]);
    client.read += n;
    if client.read == client.output.len() {
        client.output.clear();
        client.read = 0;
    }
    n as i32
}

pub(super) fn pending() -> bool { PENDING.load(Ordering::Acquire) }

pub(super) fn poll(machine: &mut impl crate::Arch, stats: &mut crate::kernel::startup::EventStats) -> bool {
    if !PENDING.swap(false, Ordering::AcqRel) { return false; }
    let mut dump = false;
    for _ in 0..MAX_CLIENTS {
        let request = {
            let mut clients = CLIENTS.lock();
            clients.entries.iter_mut().find(|c| c.queued).map(|client| {
                client.queued = false;
                (client.handle, core::mem::take(&mut client.input))
            })
        };
        let Some((handle, command)) = request else { break; };
        let (debug, output) = super::execute_local(machine, &command, stats);
        dump |= debug;
        let mut clients = CLIENTS.lock();
        if let Some(client) = clients.entries.iter_mut().find(|c| c.handle == handle) {
            client.output = output;
            client.read = 0;
            client.busy = false;
        }
    }
    dump
}
