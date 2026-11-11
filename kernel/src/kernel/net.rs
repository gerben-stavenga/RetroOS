//! Common RetroOS networking: sockets, TCP/UDP/IP, DHCP and Ethernet devices.
//! Linux, OS/2 and Windows adapters translate their ABIs into this typed API.
//! No guest sockaddr layout, errno value or poll mask belongs in this layer.

pub use arch_abi::net::{
    Endpoint, Error, Readiness, Result, Shutdown, SocketHooks, SocketKind, SocketOption,
};

static mut SOCKET_BACKEND: Option<SocketHooks> = None;

/// Install the native socket hooks. Single-threaded boot context (the entry
/// calls this before `startup`), safe by the same argument as `install_portio`.
pub fn install_socket_backend(hooks: SocketHooks) {
    unsafe {
        SOCKET_BACKEND = Some(hooks);
    }
}

pub(crate) mod local;
mod config;
mod stack;
pub(crate) mod lan;

/// The Ethernet seam shared by the IP stack and NIC drivers. Packets exclude
/// the FCS; ownership transfers out of DMA before receive returns.
pub trait EthernetDevice: Send {
    fn mac_address(&self) -> [u8; 6];
    fn receive(&mut self) -> Option<alloc::vec::Vec<u8>>;
    fn can_transmit(&mut self) -> bool;
    fn transmit(&mut self, frame: &[u8]) -> bool;
}

pub fn init<A: crate::Arch>(machine: &mut A) {
    if socket_backend_installed() {
        return;
    }
    crate::kernel::wifi::init(machine);
    if let Some(device) = crate::kernel::drivers::virtio_net::probe(machine) {
        config::mount();
        stack::install(alloc::boxed::Box::new(device));
    } else if let Some(device) = crate::kernel::drivers::e1000::probe(machine) {
        config::mount();
        stack::install(alloc::boxed::Box::new(device));
    }
    // Only wired devices installed during boot may wait for an initial lease.
    // Wi-Fi attaches later from poll(), while guests and UI are already live.
    if stack::installed() {
        stack::wait_for_initial_lease();
    }
}

pub(crate) fn install_wifi(device: alloc::boxed::Box<dyn EthernetDevice>) {
    if !stack::installed() {
        config::mount();
        stack::install(device);
    }
}
pub fn poll() {
    let _stall = crate::kernel::portio::StallWatch::new("network poll");
    crate::kernel::wifi::poll();
    stack::poll();
    lan::poll();
}
pub fn native_backend() -> bool {
    stack::installed()
}
pub fn socket_kind(h: i32) -> Result<SocketKind> { if local::is_local(h) { return Ok(SocketKind::Tcp); } stack::socket_kind(h) }
pub fn nonblocking(h: i32) -> bool {
    if local::is_local(h) { return local::nonblocking(h); }
    stack::nonblocking(h)
}
pub fn available_bytes(h: i32) -> Result<i32> {
    if local::is_local(h) { return local::available(h); }
    if native_backend() { stack::available_bytes(h) } else { Err(Error::Unsupported) }
}
pub fn set_nonblocking(h: i32, value: bool) {
    if local::is_local(h) { local::set_nonblocking(h, value); return; }
    stack::set_nonblocking(h, value);
}
pub fn add_ref(h: i32) {
    if local::is_local(h) { local::add_ref(h); return; }
    stack::add_ref(h);
}
pub fn receive_errors(h: i32) -> Result<bool> {
    stack::receive_errors(h)
}
pub fn socket_error(h: i32) -> Result<Option<Error>> {
    if local::is_local(h) { return local::available(h).map(|_| None); }
    if native_backend() {
        stack::socket_error(h)
    } else {
        Ok(None)
    }
}
pub fn readiness(h: i32) -> Readiness {
    if local::is_local(h) { return local::readiness(h); }
    if native_backend() {
        stack::readiness(h)
    } else {
        Readiness {
            readable: true,
            writable: true,
            ..Readiness::default()
        }
    }
}

pub fn read_sequence(h: i32) -> u64 {
    if local::is_local(h) { local::read_sequence(h) }
    else if native_backend() { stack::read_sequence(h) }
    else { 0 }
}

/// Whether a socket backend is installed.
pub fn socket_backend_installed() -> bool {
    // Copy the Option out (Copy) so we never reference the mutable static —
    // an error under edition 2024.
    unsafe { SOCKET_BACKEND }.is_some()
}

#[inline]
fn backend() -> Option<SocketHooks> {
    unsafe { SOCKET_BACKEND }
}

pub fn socket(kind: SocketKind, nonblocking: bool) -> Result<i32> {
    backend()
        .ok_or(Error::Unavailable)
        .and_then(|b| (b.socket)(kind, nonblocking))
}
pub fn connect(h: i32, addr: Endpoint) -> Result<i32> {
    backend()
        .ok_or(Error::Unavailable)
        .and_then(|b| (b.connect)(h, addr))
}
pub fn bind(h: i32, addr: Endpoint) -> Result<i32> {
    backend()
        .ok_or(Error::Unavailable)
        .and_then(|b| (b.bind)(h, addr))
}
pub fn listen(h: i32, backlog: i32) -> Result<i32> {
    backend()
        .ok_or(Error::Unavailable)
        .and_then(|b| (b.listen)(h, backlog))
}
pub fn accept(h: i32, addr: &mut Option<Endpoint>) -> Result<i32> {
    backend()
        .ok_or(Error::Unavailable)
        .and_then(|b| (b.accept)(h, addr))
}
pub fn sendto(h: i32, buf: &[u8], addr: Option<Endpoint>) -> Result<i32> {
    backend()
        .ok_or(Error::Unavailable)
        .and_then(|b| (b.sendto)(h, buf, addr))
}
pub fn recvfrom(h: i32, buf: &mut [u8], peek: bool, addr: &mut Option<Endpoint>) -> Result<i32> {
    backend()
        .ok_or(Error::Unavailable)
        .and_then(|b| (b.recvfrom)(h, buf, peek, addr))
}
pub fn setsockopt(h: i32, option: SocketOption) -> Result<i32> {
    backend()
        .ok_or(Error::Unavailable)
        .and_then(|b| (b.setsockopt)(h, option))
}
pub fn getsockname(h: i32, addr: &mut Option<Endpoint>) -> Result<i32> {
    backend()
        .ok_or(Error::Unavailable)
        .and_then(|b| (b.getsockname)(h, addr))
}
pub fn getpeername(h: i32, addr: &mut Option<Endpoint>) -> Result<i32> {
    backend()
        .ok_or(Error::Unavailable)
        .and_then(|b| (b.getpeername)(h, addr))
}
pub fn shutdown(h: i32, how: Shutdown) -> Result<i32> {
    backend()
        .ok_or(Error::Unavailable)
        .and_then(|b| (b.shutdown)(h, how))
}
pub fn close(h: i32) {
    if local::is_local(h) { local::close(h); return; }
    if let Some(b) = backend() {
        (b.close)(h);
    }
}

pub(crate) fn needs_poll() -> bool {
    native_backend() || crate::kernel::wifi::present() || lan::needs_poll()
}
