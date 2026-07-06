//! Socket layer — backend-injected, mirroring the host-fs "punch-through".
//!
//! The kernel is `no_std` and backend-agnostic. On HOSTED the kernel runs
//! native in the host process, so instead of a TCP/IP stack we proxy the Linux
//! socket syscalls straight to the host's `std::net`, injected as a fn-pointer
//! table (`SocketHooks`) exactly like `hostfs::HostBackendHooks`. On METAL no
//! backend is installed yet — the wrappers below return `-ENOSYS`; the real
//! metal path (a NIC driver + smoltcp filling the same hooks) is a follow-up.
//!
//! Signatures are primitive-only so no kernel type crosses into `arch-interp`:
//! raw `sockaddr` bytes travel as `&[u8]`, parsed on the host side.

/// The installed native socket hook table. `socket`/`accept` return a handle
/// (>= 0) or a negative errno; the byte-buffer calls return bytes moved or a
/// negative errno. `addr_out` buffers are filled with a raw `sockaddr_in`.
#[derive(Clone, Copy)]
pub struct SocketHooks {
    pub socket: fn(i32, i32, i32) -> i32,
    pub connect: fn(i32, &[u8]) -> i32,
    pub bind: fn(i32, &[u8]) -> i32,
    pub listen: fn(i32, i32) -> i32,
    /// Accept a connection: returns a new handle (>= 0) or -errno; writes the
    /// peer's `sockaddr_in` into `addr_out` (needs >= 16 bytes).
    pub accept: fn(i32, &mut [u8]) -> i32,
    pub sendto: fn(i32, &[u8], i32, &[u8]) -> i32,
    pub recvfrom: fn(i32, &mut [u8], i32, &mut [u8]) -> i32,
    pub setsockopt: fn(i32, i32, i32, &[u8]) -> i32,
    /// Fill `addr_out` with the local/peer `sockaddr_in`; returns its length.
    pub getsockname: fn(i32, &mut [u8]) -> i32,
    pub getpeername: fn(i32, &mut [u8]) -> i32,
    pub shutdown: fn(i32, i32) -> i32,
    pub close: fn(i32),
}

static mut SOCKET_BACKEND: Option<SocketHooks> = None;

/// Install the native socket hooks. Single-threaded boot context (the entry
/// calls this before `startup`), safe by the same argument as `install_portio`.
pub fn install_socket_backend(hooks: SocketHooks) {
    unsafe { SOCKET_BACKEND = Some(hooks); }
}

/// Whether a socket backend is installed (false on metal for now).
pub fn socket_backend_installed() -> bool {
    // Copy the Option out (Copy) so we never reference the mutable static —
    // an error under edition 2024.
    unsafe { SOCKET_BACKEND }.is_some()
}

#[inline]
fn backend() -> Option<SocketHooks> {
    unsafe { SOCKET_BACKEND }
}

/// -ENOSYS: what every wrapper returns when no backend is installed, so the
/// Linux personality degrades cleanly (a program's socket() fails) rather than
/// panicking on metal.
const ENOSYS: i32 = -38;

pub fn socket(domain: i32, ty: i32, proto: i32) -> i32 {
    backend().map_or(ENOSYS, |b| (b.socket)(domain, ty, proto))
}
pub fn connect(h: i32, addr: &[u8]) -> i32 {
    backend().map_or(ENOSYS, |b| (b.connect)(h, addr))
}
pub fn bind(h: i32, addr: &[u8]) -> i32 {
    backend().map_or(ENOSYS, |b| (b.bind)(h, addr))
}
pub fn listen(h: i32, backlog: i32) -> i32 {
    backend().map_or(ENOSYS, |b| (b.listen)(h, backlog))
}
pub fn accept(h: i32, addr_out: &mut [u8]) -> i32 {
    backend().map_or(ENOSYS, |b| (b.accept)(h, addr_out))
}
pub fn sendto(h: i32, buf: &[u8], flags: i32, addr: &[u8]) -> i32 {
    backend().map_or(ENOSYS, |b| (b.sendto)(h, buf, flags, addr))
}
pub fn recvfrom(h: i32, buf: &mut [u8], flags: i32, addr_out: &mut [u8]) -> i32 {
    backend().map_or(ENOSYS, |b| (b.recvfrom)(h, buf, flags, addr_out))
}
pub fn setsockopt(h: i32, level: i32, optname: i32, opt: &[u8]) -> i32 {
    backend().map_or(ENOSYS, |b| (b.setsockopt)(h, level, optname, opt))
}
pub fn getsockname(h: i32, addr_out: &mut [u8]) -> i32 {
    backend().map_or(ENOSYS, |b| (b.getsockname)(h, addr_out))
}
pub fn getpeername(h: i32, addr_out: &mut [u8]) -> i32 {
    backend().map_or(ENOSYS, |b| (b.getpeername)(h, addr_out))
}
pub fn shutdown(h: i32, how: i32) -> i32 {
    backend().map_or(ENOSYS, |b| (b.shutdown)(h, how))
}
pub fn close(h: i32) {
    if let Some(b) = backend() { (b.close)(h); }
}
