//! Personality-independent socket contract. Guest address layouts, option
//! numbers, errno values and poll masks belong in each personality adapter.
//! Shared here so the kernel and hosted backend use the same Rust types.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Endpoint {
    pub address: [u8; 4],
    pub port: u16,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketKind {
    Tcp,
    Udp,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shutdown {
    Read,
    Write,
    Both,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SocketOption {
    ReuseAddress(bool),
    TcpNoDelay(bool),
    /// Register interest in asynchronous datagram network errors.
    ReceiveErrors(bool),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unavailable,
    InvalidHandle,
    InvalidArgument,
    WouldBlock,
    TooManySockets,
    AddressInUse,
    AddressUnavailable,
    NotConnected,
    AlreadyConnected,
    ConnectionRefused,
    AlreadyConnecting,
    InProgress,
    NetworkUnreachable,
    BrokenPipe,
    MessageTooLarge,
    DestinationRequired,
    Unsupported,
    UnsupportedOption,
    Io,
}
pub type Result<T> = core::result::Result<T, Error>;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Readiness {
    pub readable: bool,
    pub writable: bool,
    pub error: bool,
    pub closed: bool,
    pub invalid: bool,
}

/// The native stack returns `WouldBlock` when progress is needed; personalities
/// choose how to suspend a caller or report that state. The hosted TCP backend
/// currently retains synchronous host I/O. Counts and handles are nonnegative;
/// control operations return zero on success.
/// Handles identify common RetroOS sockets, independent of guest fd/handles.
#[derive(Clone, Copy)]
pub struct SocketHooks {
    pub socket: fn(SocketKind, bool) -> Result<i32>,
    pub connect: fn(i32, Endpoint) -> Result<i32>,
    pub bind: fn(i32, Endpoint) -> Result<i32>,
    pub listen: fn(i32, i32) -> Result<i32>,
    pub accept: fn(i32, &mut Option<Endpoint>) -> Result<i32>,
    pub sendto: fn(i32, &[u8], Option<Endpoint>) -> Result<i32>,
    pub recvfrom: fn(i32, &mut [u8], bool, &mut Option<Endpoint>) -> Result<i32>,
    pub setsockopt: fn(i32, SocketOption) -> Result<i32>,
    pub getsockname: fn(i32, &mut Option<Endpoint>) -> Result<i32>,
    pub getpeername: fn(i32, &mut Option<Endpoint>) -> Result<i32>,
    pub shutdown: fn(i32, Shutdown) -> Result<i32>,
    pub close: fn(i32),
}
