//! HostFS serial client and session protocol.
//!
//! This module combines HostFS protocol policy with a byte-oriented UART. The
//! framing implementation itself lives in the sibling transport-neutral
//! `frame` module.

use super::frame::{self, MAX_BODY, MAX_FRAME_PAYLOAD};
use crate::kernel::drivers::uart16550::{Uart16550, UartConfig};
use arch_abi::ComPort;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

static HOSTFS_PORT: AtomicU8 = AtomicU8::new(1);
// Bounded rather than time-based because this transport has no Arch clock
// handle. This is a short, few-second failure when the peer is gone.
const UART_WAIT_POLLS: u32 = 1_000_000;
pub(crate) const HOSTFS_IO_ERROR: i32 = -110; // ETIMEDOUT / HostFS unavailable
pub(crate) const MAX_READ_CHUNK: usize = MAX_FRAME_PAYLOAD - 8;
pub(crate) const MAX_WRITE_CHUNK: usize = MAX_FRAME_PAYLOAD - 12;

pub(crate) struct RequestWriter {
    data: [u8; MAX_FRAME_PAYLOAD],
    len: usize,
}

impl RequestWriter {
    pub(crate) fn new() -> Self {
        Self {
            data: [0; MAX_FRAME_PAYLOAD],
            len: 0,
        }
    }

    pub(crate) fn push_u16(&mut self, value: u16) -> bool {
        self.push_bytes(&value.to_le_bytes())
    }

    pub(crate) fn push_u32(&mut self, value: u32) -> bool {
        self.push_bytes(&value.to_le_bytes())
    }

    pub(crate) fn push_bytes(&mut self, bytes: &[u8]) -> bool {
        let Some(end) = self.len.checked_add(bytes.len()) else {
            return false;
        };
        if end > self.data.len() {
            return false;
        }
        self.data[self.len..end].copy_from_slice(bytes);
        self.len = end;
        true
    }

    pub(crate) fn push_path(&mut self, path: &[u8]) -> bool {
        path.len() <= u16::MAX as usize && self.push_u16(path.len() as u16) && self.push_bytes(path)
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.data[..self.len]
    }
}

pub(crate) struct ResponseReader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> ResponseReader<'a> {
    pub(crate) fn new(data: &'a [u8], expected_len: usize) -> Option<Self> {
        (data.len() == expected_len).then_some(Self { data, offset: 0 })
    }

    pub(crate) fn read_i32(&mut self) -> Option<i32> {
        Some(i32::from_le_bytes(self.take::<4>()?))
    }

    pub(crate) fn read_u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take::<4>()?))
    }

    pub(crate) fn read_u8(&mut self) -> Option<u8> {
        Some(*self.take::<1>()?.first()?)
    }

    pub(crate) fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.offset)
    }

    fn take<const N: usize>(&mut self) -> Option<[u8; N]> {
        let end = self.offset.checked_add(N)?;
        let bytes = self.data.get(self.offset..end)?;
        self.offset = end;
        bytes.try_into().ok()
    }
}

const TYPE_HELLO: u8 = 0xf0;
const TYPE_HELLO_ACK: u8 = 0xf1;
static HOSTFS_READY: AtomicBool = AtomicBool::new(false);
static HOSTFS_SESSION: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0x1357_9bdf);

const HOSTFS_STATE_UNKNOWN: u8 = 0;
const HOSTFS_STATE_DISCONNECTED: u8 = 1;
const HOSTFS_STATE_CONNECTED: u8 = 2;
static HOSTFS_STATE: AtomicU8 = AtomicU8::new(HOSTFS_STATE_UNKNOWN);

fn set_link_state(state: u8) {
    if HOSTFS_STATE.swap(state, Ordering::Relaxed) == state {
        return;
    }
    match state {
        HOSTFS_STATE_CONNECTED => crate::println!("hostfs: connected"),
        HOSTFS_STATE_DISCONNECTED => crate::println!("hostfs: disconnected"),
        _ => {}
    }
}

/// Select the UART used for HostFS communication.
pub fn configure(port: ComPort) {
    let selected = match port {
        ComPort::Com1 => 1,
        ComPort::Com2 => 2,
    };
    HOSTFS_PORT.store(selected, Ordering::Relaxed);
}

fn uart() -> Uart16550 {
    let port = match HOSTFS_PORT.load(Ordering::Relaxed) {
        2 => ComPort::Com2,
        _ => ComPort::Com1,
    };
    Uart16550::new(port)
}

/// Configure the selected UART and establish a framed HostFS session.
///
/// HostFS does not use modem-control status as a connection signal: QEMU's
/// Unix-socket chardev cannot reliably represent CTS/DSR. A framed HELLO/ACK
/// exchange is the connection probe; a bounded UART timeout leaves the
/// filesystem unavailable and the next operation will retry initialization.
pub fn init() -> bool {
    HOSTFS_READY.store(false, Ordering::Relaxed);
    let uart = uart();
    if !uart.is_present() {
        set_link_state(HOSTFS_STATE_DISCONNECTED);
        return false;
    }
    uart.initialize(UartConfig::UART_115200_8N1);
    let token = next_session();
    if !establish_session(token, send_raw_byte, recv_raw_byte) {
        set_link_state(HOSTFS_STATE_DISCONNECTED);
        return false;
    }
    HOSTFS_READY.store(true, Ordering::Relaxed);
    set_link_state(HOSTFS_STATE_CONNECTED);
    true
}

/// Whether the selected UART exists. HostFS availability is determined by the
/// framed handshake probe in `init`, not by CTS/DSR modem-control bits.
pub fn uart_present() -> bool {
    uart().is_present()
}

pub(crate) fn is_ready() -> bool {
    HOSTFS_READY.load(Ordering::Relaxed)
}

pub(crate) fn ensure_ready() -> bool {
    is_ready() || init()
}

fn mark_unavailable() {
    HOSTFS_READY.store(false, Ordering::Relaxed);
    set_link_state(HOSTFS_STATE_DISCONNECTED);
}

fn send_raw_byte(byte: u8) -> bool {
    if uart().write_byte(UART_WAIT_POLLS, byte).is_err() {
        mark_unavailable();
        return false;
    }
    true
}

fn send_frame(frame_type: u8, payload: &[u8]) -> bool {
    frame::send_frame(frame_type, payload, send_raw_byte)
}

fn recv_raw_byte() -> Option<u8> {
    let byte = uart().read_byte(UART_WAIT_POLLS).ok();
    if byte.is_none() {
        mark_unavailable();
    }
    byte
}

fn establish_session<S, R>(token: u32, mut send_raw: S, mut read_raw: R) -> bool
where
    S: FnMut(u8) -> bool,
    R: FnMut() -> Option<u8>,
{
    if !frame::send_frame(TYPE_HELLO, &token.to_le_bytes(), &mut send_raw) {
        return false;
    }
    let mut response = [0u8; MAX_BODY];
    loop {
        let Some((frame_type, payload_len)) = frame::recv_frame(&mut read_raw, &mut response)
        else {
            return false;
        };
        if frame_type == TYPE_HELLO_ACK
            && payload_len == 4
            && u32::from_le_bytes(response[1..5].try_into().unwrap()) == token
        {
            return true;
        }
    }
}

fn next_session() -> u32 {
    HOSTFS_SESSION
        .fetch_add(1, Ordering::Relaxed)
        .wrapping_add(1)
}

pub(crate) fn peer_hello_token(response: &[u8; MAX_BODY]) -> [u8; 4] {
    response[1..5].try_into().expect("validated HELLO token")
}

fn receive_expected(expected: u8, response: &mut [u8; MAX_BODY]) -> Option<usize> {
    receive_expected_with_io(
        expected,
        response,
        send_raw_byte,
        recv_raw_byte,
        mark_unavailable,
    )
}

fn receive_expected_with_io<S, R, U>(
    expected: u8,
    response: &mut [u8; MAX_BODY],
    mut send_raw: S,
    mut read_raw: R,
    mut on_peer_reset: U,
) -> Option<usize>
where
    S: FnMut(u8) -> bool,
    R: FnMut() -> Option<u8>,
    U: FnMut(),
{
    loop {
        let (frame_type, payload_len) = frame::recv_frame(&mut read_raw, response)?;
        if frame_type == expected {
            response.copy_within(1..1 + payload_len, 0);
            return Some(payload_len);
        }
        // A peer HELLO is an explicit session reset. Acknowledge it, then make
        // the current operation fail; the next operation starts normally.
        if frame_type == TYPE_HELLO && payload_len == 4 {
            let token = peer_hello_token(response);
            let _ = frame::send_frame(TYPE_HELLO_ACK, &token, &mut send_raw);
            on_peer_reset();
            return None;
        }
    }
}

pub(crate) fn request(cmd: u8, payload: &[u8], response: &mut [u8; MAX_BODY]) -> Option<usize> {
    if !send_frame(cmd, payload) {
        return None;
    }
    receive_expected(0x80 | cmd, response)
}

pub(crate) fn close(handle: u64) -> bool {
    send_frame(CMD_CLOSE, &(handle as u32).to_le_bytes())
}

pub(crate) const CMD_OPEN: u8 = 0x01;
pub(crate) const CMD_READ: u8 = 0x02;
pub(crate) const CMD_CLOSE: u8 = 0x03;
pub(crate) const CMD_STAT: u8 = 0x04;
pub(crate) const CMD_READDIR: u8 = 0x05;
pub(crate) const CMD_CREATE: u8 = 0x06;
pub(crate) const CMD_WRITE: u8 = 0x07;
pub(crate) const CMD_MKDIR: u8 = 0x08;

#[cfg(test)]
mod tests {
    use super::{
        MAX_BODY, ResponseReader, establish_session, peer_hello_token, receive_expected_with_io,
    };
    use crate::kernel::fs::hostfs::frame::{recv_frame, send_frame};
    use alloc::vec::Vec;

    #[test]
    fn peer_hello_token_excludes_frame_type() {
        let expected = [0x12, 0x34, 0x56, 0x78];
        let mut response = [0u8; MAX_BODY];
        response[0] = 0xf0;
        response[1..5].copy_from_slice(&expected);

        assert_eq!(peer_hello_token(&response), expected);
    }

    #[test]
    fn peer_hello_resets_operation_and_next_handshake_is_fresh() {
        let peer_token = [0x12, 0x34, 0x56, 0x78];
        let mut incoming = Vec::new();
        assert!(send_frame(0xf0, &peer_token, |byte| {
            incoming.push(byte);
            true
        }));
        let mut outgoing = Vec::new();
        let mut offset = 0;
        let mut reset = false;
        let mut response = [0u8; MAX_BODY];
        assert_eq!(
            receive_expected_with_io(
                0x81,
                &mut response,
                |byte| {
                    outgoing.push(byte);
                    true
                },
                || {
                    let byte = incoming.get(offset).copied();
                    offset += 1;
                    byte
                },
                || reset = true,
            ),
            None
        );
        assert!(reset);

        let mut ack = Vec::new();
        let next_token: u32 = 0x7856_3412;
        assert!(send_frame(0xf1, &next_token.to_le_bytes(), |byte| {
            ack.push(byte);
            true
        }));
        let mut ack_offset = 0;
        assert!(establish_session(
            next_token,
            |byte| {
                outgoing.push(byte);
                true
            },
            || {
                let byte = ack.get(ack_offset).copied();
                ack_offset += 1;
                byte
            },
        ));

        let mut decoded = [0u8; MAX_BODY];
        let mut out_offset = 0;
        assert_eq!(
            recv_frame(
                &mut || {
                    let byte = outgoing.get(out_offset).copied();
                    out_offset += 1;
                    byte
                },
                &mut decoded,
            ),
            Some((0xf1, 4))
        );
        assert_eq!(&decoded[1..5], &peer_token);
        assert_eq!(
            recv_frame(
                &mut || {
                    let byte = outgoing.get(out_offset).copied();
                    out_offset += 1;
                    byte
                },
                &mut decoded,
            ),
            Some((0xf0, 4))
        );
        assert_eq!(&decoded[1..5], &next_token.to_le_bytes());
    }

    #[test]
    fn response_reader_tracks_exact_consumption() {
        let mut reader = ResponseReader::new(&[1, 0, 0, 0, 0x7f], 5).unwrap();
        assert_eq!(reader.remaining(), 5);
        assert_eq!(reader.read_i32(), Some(1));
        assert_eq!(reader.remaining(), 1);
        assert_eq!(reader.read_u8(), Some(0x7f));
        assert_eq!(reader.remaining(), 0);
    }
}
