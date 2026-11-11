//! Kernel-local byte streams. They never allocate an IP port or reach a NIC.
use super::{Error, Readiness, Result};
use alloc::{collections::{BTreeMap, VecDeque}, vec::Vec};
use spin::Mutex;
pub type Address = (usize, Vec<u8>);
#[derive(Clone, Copy, Default)]
pub struct Credentials { pub pid: i32, pub uid: u32, pub gid: u32 }
#[derive(Clone, Copy)]
pub struct Node { pub mode: u16, pub ino: u64, pub mtime: u32, owner: Option<i32> }
struct Stream {
    refs: usize, nonblock: bool, credentials: Credentials, peer_credentials: Option<Credentials>,
    name: Vec<u8>, peer_name: Vec<u8>, key: Option<Address>, peer: Option<i32>, connected: bool,
    listening: bool, backlog: usize, pending: VecDeque<i32>, bytes: VecDeque<u8>,
    eof: bool, read_closed: bool, write_closed: bool,
    read_sequence: u64,
}
impl Stream {
    fn new(nonblock: bool, credentials: Credentials) -> Self {
        Self { refs: 1, nonblock, credentials, peer_credentials: None,
            name: Vec::new(), peer_name: Vec::new(), key: None, peer: None,
            connected: false, listening: false, backlog: 1, pending: VecDeque::new(),
            bytes: VecDeque::new(), eof: false, read_closed: false, write_closed: false, read_sequence: 0 }
    }
}
const BASE: i32 = 0x40000000;
const CAPACITY: usize = 65536;
struct Local { streams: Vec<Option<Stream>>, nodes: BTreeMap<Address, Node>, next_inode: u64 }
static LOCAL: Mutex<Local> = Mutex::new(Local { streams: Vec::new(), nodes: BTreeMap::new(), next_inode: 1 });
static HAS_NODES: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
pub fn is_local(h: i32) -> bool { h >= BASE }
pub fn has_nodes() -> bool { HAS_NODES.load(core::sync::atomic::Ordering::Relaxed) }
impl Local {
    fn get(&self, h: i32) -> Result<&Stream> {
        self.streams.get(h.checked_sub(BASE).ok_or(Error::InvalidHandle)? as usize)
            .and_then(Option::as_ref).ok_or(Error::InvalidHandle)
    }
    fn get_mut(&mut self, h: i32) -> Result<&mut Stream> {
        self.streams.get_mut(h.checked_sub(BASE).ok_or(Error::InvalidHandle)? as usize)
            .and_then(Option::as_mut).ok_or(Error::InvalidHandle)
    }
    fn add(&mut self, stream: Stream) -> Result<i32> {
        if let Some(i) = self.streams.iter().position(Option::is_none) { self.streams[i] = Some(stream); return Ok(BASE + i as i32); }
        if self.streams.len() == 4096 { return Err(Error::TooManySockets); }
        let h = BASE + self.streams.len() as i32; self.streams.push(Some(stream)); Ok(h)
    }
    fn close(&mut self, h: i32) {
        let Ok(stream) = self.get_mut(h) else { return; };
        stream.refs -= 1; if stream.refs != 0 { return; }
        let stream = self.streams[(h - BASE) as usize].take().unwrap();
        if let Some(peer) = stream.peer && let Ok(peer) = self.get_mut(peer) { peer.peer = None; peer.eof = true; }
        if let Some(key) = stream.key && self.nodes.get(&key).is_some_and(|node| node.owner == Some(h)) {
            if key.0 == 0 { self.nodes.remove(&key); }
            else { self.nodes.get_mut(&key).unwrap().owner = None; }
        }
        for pending in stream.pending { self.close(pending); }
    }
}
pub fn socket(nonblock: bool, credentials: Credentials) -> Result<i32> { LOCAL.lock().add(Stream::new(nonblock, credentials)) }
pub fn add_ref(h: i32) { if let Ok(stream) = LOCAL.lock().get_mut(h) { stream.refs += 1; } }
pub fn close(h: i32) { LOCAL.lock().close(h); }
pub fn nonblocking(h: i32) -> bool { LOCAL.lock().get(h).is_ok_and(|s| s.nonblock) }
pub fn set_nonblocking(h: i32, value: bool) { if let Ok(s) = LOCAL.lock().get_mut(h) { s.nonblock = value; } }
pub fn bind(h: i32, key: Address, name: Vec<u8>, mode: u16) -> Result<i32> {
    let mut local = LOCAL.lock();
    if local.get(h)?.key.is_some() || local.get(h)?.connected { return Err(Error::InvalidArgument); }
    if local.nodes.contains_key(&key) { return Err(Error::AddressInUse); }
    let ino = 0x8000000000000000 | local.next_inode; local.next_inode += 1;
    local.nodes.insert(key.clone(), Node { mode: 0o140000 | (mode & 0o777), ino,
        mtime: crate::kernel::clock::rtc_unix_timestamp().unwrap_or(0), owner: Some(h) });
    let stream = local.get_mut(h)?; stream.key = Some(key); stream.name = name;
    HAS_NODES.store(true, core::sync::atomic::Ordering::Relaxed); Ok(0)
}
pub fn node(key: &Address) -> Option<Node> { LOCAL.lock().nodes.get(key).copied() }
pub fn chmod(key: &Address, mode: u16) -> bool {
    let mut local = LOCAL.lock(); let Some(node) = local.nodes.get_mut(key) else { return false; };
    node.mode = 0o140000 | (mode & 0o777); true
}
pub fn unlink(key: &Address) -> bool { LOCAL.lock().nodes.remove(key).is_some() }
pub fn children(filesystem: usize, parent: &[u8]) -> Vec<(Vec<u8>, Node)> {
    let local = LOCAL.lock();
    local.nodes.iter().filter_map(|((fs, path), node)| {
        if *fs != filesystem { return None; }
        let (directory, name) = match path.iter().rposition(|b| *b == b'/') {
            Some(n) => (&path[..n], &path[n+1..]), None => (&b""[..], path.as_slice()),
        };
        (directory == parent).then(|| (name.to_vec(), *node))
    }).collect()
}
pub fn listen(h: i32, backlog: i32, credentials: Credentials) -> Result<i32> {
    let mut local = LOCAL.lock(); let stream = local.get_mut(h)?;
    if stream.key.is_none() || stream.connected { return Err(Error::InvalidArgument); }
    stream.listening = true; stream.backlog = backlog.clamp(1,128) as usize; stream.credentials = credentials; Ok(0)
}
pub fn connect(h: i32, key: &Address, credentials: Credentials) -> Result<i32> {
    let mut local = LOCAL.lock();
    if local.get(h)?.connected { return Err(Error::AlreadyConnected); }
    if local.get(h)?.listening { return Err(Error::InvalidArgument); }
    let listener = local.nodes.get(key).and_then(|node| node.owner).ok_or(Error::ConnectionRefused)?;
    let server = local.get(listener)?;
    if !server.listening { return Err(Error::ConnectionRefused); }
    if server.pending.len() >= server.backlog { return Err(Error::WouldBlock); }
    let mut accepted = Stream::new(false, server.credentials);
    accepted.name = server.name.clone(); accepted.peer_name = local.get(h)?.name.clone();
    accepted.peer = Some(h); accepted.connected = true; accepted.peer_credentials = Some(credentials);
    let server_name = server.name.clone(); let server_credentials = server.credentials;
    let accepted = local.add(accepted)?;
    let client = local.get_mut(h)?;
    client.peer = Some(accepted); client.connected = true; client.credentials = credentials;
    client.peer_name = server_name; client.peer_credentials = Some(server_credentials);
    let listener = local.get_mut(listener)?;
    listener.pending.push_back(accepted);
    listener.read_sequence = listener.read_sequence.wrapping_add(1);
    Ok(0)
}
pub fn accept(h: i32) -> Result<i32> {
    let mut local = LOCAL.lock(); let stream = local.get_mut(h)?;
    if !stream.listening { return Err(Error::InvalidArgument); }
    stream.pending.pop_front().ok_or(Error::WouldBlock)
}
pub fn send(h: i32, bytes: &[u8]) -> Result<i32> {
    let mut local = LOCAL.lock(); let stream = local.get(h)?;
    if !stream.connected { return Err(Error::NotConnected); }
    if stream.write_closed { return Err(Error::BrokenPipe); }
    let peer = stream.peer.ok_or(Error::BrokenPipe)?; let peer = local.get_mut(peer)?;
    if peer.read_closed { return Err(Error::BrokenPipe); }
    if bytes.is_empty() { return Ok(0); }
    let n = bytes.len().min(CAPACITY.saturating_sub(peer.bytes.len()));
    if n == 0 { return Err(Error::WouldBlock); }
    peer.bytes.extend(bytes[..n].iter().copied());
    peer.read_sequence = peer.read_sequence.wrapping_add(1);
    Ok(n as i32)
}
pub fn receive(h: i32, bytes: &mut [u8], peek: bool) -> Result<i32> {
    let mut local = LOCAL.lock(); let stream = local.get_mut(h)?;
    if !stream.connected { return Err(Error::NotConnected); }
    if bytes.is_empty() || stream.read_closed { return Ok(0); }
    let n = bytes.len().min(stream.bytes.len());
    if n == 0 && !stream.eof { return Err(Error::WouldBlock); }
    for (out, input) in bytes.iter_mut().zip(stream.bytes.iter()).take(n) { *out = *input; }
    if !peek { stream.bytes.drain(..n); } Ok(n as i32)
}
pub fn name(h: i32, peer: bool) -> Result<Vec<u8>> {
    let local = LOCAL.lock(); let stream = local.get(h)?;
    if peer && !stream.connected { return Err(Error::NotConnected); }
    Ok(if peer { stream.peer_name.clone() } else { stream.name.clone() })
}
pub fn credentials(h: i32) -> Result<Credentials> { LOCAL.lock().get(h)?.peer_credentials.ok_or(Error::NotConnected) }
pub fn available(h: i32) -> Result<i32> { Ok(LOCAL.lock().get(h)?.bytes.len() as i32) }
pub fn read_sequence(h: i32) -> u64 { LOCAL.lock().get(h).map_or(0, |stream| stream.read_sequence) }
pub fn shutdown(h: i32, read: bool, write: bool) -> Result<i32> {
    let mut local = LOCAL.lock(); let stream = local.get_mut(h)?;
    if !stream.connected { return Err(Error::NotConnected); }
    if read { stream.read_closed = true; stream.bytes.clear(); }
    if write { stream.write_closed = true; }
    let peer = stream.peer;
    if write && let Some(peer) = peer && let Ok(peer) = local.get_mut(peer) { peer.eof = true; }
    Ok(0)
}
pub fn readiness(h: i32) -> Readiness {
    let local = LOCAL.lock(); let Ok(stream) = local.get(h) else { return Readiness { invalid: true, ..Readiness::default() }; };
    let writable = stream.connected && !stream.write_closed && stream.peer.and_then(|h| local.get(h).ok())
        .is_some_and(|peer| !peer.read_closed && peer.bytes.len() < CAPACITY);
    Readiness { readable: if stream.listening { !stream.pending.is_empty() } else { !stream.bytes.is_empty() || stream.eof || stream.read_closed },
        writable, closed: stream.connected && stream.peer.is_none(), error: false, invalid: false }
}
