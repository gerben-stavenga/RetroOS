//! Novell DOS IPX interface over an OSD-managed RetroOS LAN.
//! Guest ECBs stay in conventional memory; bounded datagrams use native UDP.
use super::{DosState, ResumeCallback, machine, mode_transitions};
use crate::kernel::net::lan;
use crate::{Arch, Regs};
use alloc::{collections::VecDeque, vec::Vec};

const HEADER: usize = 30;
const MAX_PACKET: usize = 1424;
const MAX_SOCKETS: usize = 150;
const MAX_PENDING: usize = 256;
const SUCCESS: u8 = 0;
const CANCELLED: u8 = 0xfc;
const MALFORMED: u8 = 0xfd;
const FAILURE: u8 = 0xff;
fn now_ms() -> u64 {
    crate::kernel::portio::now_ns() / 1_000_000
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Far {
    segment: u16,
    offset: u16,
}
impl Far {
    fn linear(self) -> usize {
        (self.segment as usize) * 16 + self.offset as usize
    }
    fn valid(self, len: usize) -> bool {
        self.offset as usize + len <= 0x10000 && self.linear() + len <= 0xa0000
    }
    fn byte<A: Arch>(self, m: &A, offset: usize) -> u8 {
        m.read::<u8>(self.linear() + offset)
    }
    fn word<A: Arch>(self, m: &A, offset: usize) -> u16 {
        m.read::<u16>(self.linear() + offset)
    }
    fn put<A: Arch>(self, m: &mut A, offset: usize, value: u8) {
        m.write::<u8>(self.linear() + offset, value);
    }
    fn esr<A: Arch>(self, m: &A) -> Far {
        Far {
            offset: self.word(m, 4),
            segment: self.word(m, 6),
        }
    }
}
#[derive(Clone, Copy)]
struct Socket {
    number: u16,
    owner: u16,
    persistent: bool,
}
#[derive(Clone, Copy)]
struct Pending {
    ecb: Far,
    socket: u16,
    owner: u16,
    deadline: Option<u64>,
}
#[derive(Clone, Copy)]
struct Completion {
    ecb: Far,
    esr: Far,
    owner: u16,
    event: bool,
}

pub(crate) struct IpxState {
    active: bool,
    session: Option<lan::Session>,
    address: Option<[u8; 10]>,
    sockets: Vec<Socket>,
    pending: Vec<Pending>,
    completed: VecDeque<Completion>,
    saved: Option<[u64; 7]>,
}
impl IpxState {
    pub fn new() -> Self {
        Self {
            active: false,
            session: None,
            address: None,
            sockets: Vec::new(),
            pending: Vec::new(),
            completed: VecDeque::new(),
            saved: None,
        }
    }
    fn finish<A: Arch>(&mut self, m: &mut A, request: Pending, code: u8) {
        request.ecb.put(m, 9, code);
        request.ecb.put(m, 8, 0);
        let esr = request.ecb.esr(m);
        if esr.segment != 0 || esr.offset != 0 {
            // Submission limits reserve room for all outstanding completions.
            self.completed.push_back(Completion {
                ecb: request.ecb,
                esr,
                owner: request.owner,
                event: request.deadline.is_some(),
            });
        }
    }
    fn ready(&self) -> bool {
        self.address.is_some()
    }

    pub fn poll<A: Arch>(&mut self, m: &mut A) {
        if !self.active {
            return;
        }
        if self.session.is_some_and(|session| !lan::valid(session)) {
            self.session = None;
            self.address = None;
            while let Some(request) = self.pending.pop() {
                self.finish(m, request, CANCELLED);
            }
            self.sockets.clear();
        }
        if self.session.is_none() {
            self.session = lan::attach();
            if let Some(session) = self.session {
                self.address = Some(session.address);
            }
        }
        let Some(session) = self.session else { return };
        let now = now_ms();
        for _ in 0..32 {
            let Some(packet) = lan::receive(session) else {
                break;
            };
            if !valid_packet(&packet) {
                continue;
            }
            let packet = packet.as_slice();
            let address = self.address.unwrap();
            if packet[6..10] != address[..4]
                || (packet[10..16] != address[4..] && packet[10..16] != [0xff; 6])
            {
                continue;
            }
            let socket = u16::from_be_bytes([packet[16], packet[17]]);
            if let Some(index) = self
                .pending
                .iter()
                .position(|p| p.deadline.is_none() && p.socket == socket)
            {
                let request = self.pending.remove(index);
                let code = match fragments(m, request.ecb) {
                    Some(buffers)
                        if buffers.iter().map(|(_, n)| n).sum::<usize>() >= packet.len() =>
                    {
                        let mut offset = 0;
                        for (dest, len) in buffers {
                            let count = len.min(packet.len() - offset);
                            m.copy_to(dest.linear(), &packet[offset..offset + count]);
                            offset += count;
                            if offset == packet.len() {
                                break;
                            }
                        }
                        m.copy_to(request.ecb.linear() + 28, &packet[22..28]);
                        SUCCESS
                    }
                    _ => MALFORMED,
                };
                self.finish(m, request, code);
            }
        }
        let mut index = 0;
        while index < self.pending.len() {
            if self.pending[index]
                .deadline
                .is_some_and(|deadline| deadline <= now)
            {
                let request = self.pending.remove(index);
                self.finish(m, request, SUCCESS);
            } else {
                index += 1;
            }
        }
    }

    pub fn release<A: Arch>(&mut self, m: &mut A, owner: u16) {
        let numbers: Vec<_> = self
            .sockets
            .iter()
            .filter(|s| s.owner == owner && !s.persistent)
            .map(|s| s.number)
            .collect();
        for number in numbers {
            self.close(m, number);
        }
        self.pending.retain(|p| p.owner != owner);
        self.completed.retain(|p| p.owner != owner);
    }
    fn close<A: Arch>(&mut self, m: &mut A, number: u16) {
        self.sockets.retain(|s| s.number != number);
        let mut i = 0;
        while i < self.pending.len() {
            if self.pending[i].socket == number {
                let request = self.pending.remove(i);
                request.ecb.put(m, 9, CANCELLED);
                request.ecb.put(m, 8, 0);
            } else {
                i += 1;
            }
        }
        self.completed
            .retain(|p| u16::from_be_bytes([p.ecb.byte(m, 10), p.ecb.byte(m, 11)]) != number);
    }
}
impl Drop for IpxState {
    fn drop(&mut self) {
        if let Some(session) = self.session {
            lan::detach(session);
        }
    }
}

fn valid_packet(packet: &[u8]) -> bool {
    (HEADER..=MAX_PACKET).contains(&packet.len())
        && u16::from_be_bytes([packet[2], packet[3]]) as usize == packet.len()
}
fn fragments<A: Arch>(m: &A, ecb: Far) -> Option<Vec<(Far, usize)>> {
    if !ecb.valid(36) {
        return None;
    }
    let count = ecb.word(m, 34) as usize;
    if !(1..=32).contains(&count) || !ecb.valid(36 + count * 6) {
        return None;
    }
    let mut result = Vec::new();
    let mut total = 0;
    for index in 0..count {
        let offset = 36 + index * 6;
        let address = Far {
            offset: ecb.word(m, offset),
            segment: ecb.word(m, offset + 2),
        };
        let len = ecb.word(m, offset + 4) as usize;
        total += len;
        if !address.valid(len) || total > MAX_PACKET {
            return None;
        }
        result.push((address, len));
    }
    Some(result)
}
fn al(regs: &mut Regs, value: u8) {
    regs.rax = (regs.rax & !0xff) | value as u64;
}
fn installed(regs: &mut Regs) {
    al(regs, 0xff);
    regs.es = super::dos::CTRL_STUB_SEG as u64;
    regs.rdi = (regs.rdi & !0xffff) | super::dos::ctrl_slot_off(super::dos::SLOT_IPX) as u64;
}
pub(crate) fn discover<A: Arch>(
    m: &mut A,
    dos: &mut DosState<A>,
    regs: &mut Regs,
) -> Option<ResumeCallback<A>> {
    dos.ipx.active = true;
    dos.ipx.poll(m);
    if dos.ipx.ready() {
        installed(regs);
        None
    } else {
        al(regs, 0);
        None
    }
}
pub(crate) fn api<A: Arch>(m: &mut A, dos: &mut DosState<A>, regs: &mut Regs) {
    let owner = dos.current_psp;
    let state = &mut dos.ipx;
    state.active = true;
    state.poll(m);
    if !state.ready() {
        al(regs, FAILURE);
        return;
    }
    let ecb = Far {
        segment: regs.es as u16,
        offset: regs.rsi as u16,
    };
    match regs.rbx as u16 {
        0 => {
            let mut number = (regs.rdx as u16).swap_bytes();
            if state.sockets.len() >= MAX_SOCKETS {
                al(regs, 0xfe);
                return;
            }
            if number == 0 {
                number = (0x4002..0x8000)
                    .find(|n| !state.sockets.iter().any(|s| s.number == *n))
                    .unwrap();
            }
            if state.sockets.iter().any(|s| s.number == number) {
                al(regs, 0xff);
                return;
            }
            state.sockets.push(Socket {
                number,
                owner,
                persistent: regs.rax as u8 == 0xff,
            });
            regs.rdx = (regs.rdx & !0xffff) | number.swap_bytes() as u64;
            al(regs, SUCCESS);
        }
        1 => {
            state.close(m, (regs.rdx as u16).swap_bytes());
        }
        2 => {
            let dest = Far {
                segment: regs.es as u16,
                offset: regs.rdi as u16,
            };
            if !ecb.valid(10) || !dest.valid(6) {
                al(regs, FAILURE);
                return;
            }
            let mut node = [0; 6];
            m.copy_from(ecb.linear() + 4, &mut node);
            m.copy_to(dest.linear(), &node);
            regs.rcx = (regs.rcx & !0xffff) | 1;
            al(regs, SUCCESS);
        }
        3..=7 => {
            if !ecb.valid(36) {
                al(regs, FAILURE);
                return;
            }
            if regs.rbx as u16 == 6 {
                if let Some(index) = state.pending.iter().position(|p| p.ecb == ecb) {
                    let request = state.pending.remove(index);
                    state.finish(m, request, CANCELLED);
                    al(regs, SUCCESS);
                } else {
                    al(regs, 0xf9);
                }
                return;
            }
            let socket = u16::from_be_bytes([ecb.byte(m, 10), ecb.byte(m, 11)]);
            if state.pending.iter().any(|p| p.ecb == ecb)
                || state.completed.iter().any(|p| p.ecb == ecb)
                || state.pending.len() + state.completed.len() >= MAX_PENDING
            {
                al(regs, FAILURE);
                return;
            }
            let mut request = Pending {
                ecb,
                socket,
                owner,
                deadline: None,
            };
            if matches!(regs.rbx as u16, 5 | 7) {
                request.deadline =
                    Some(now_ms() + (regs.rax as u16 as u64 * 65536 * 1000).div_ceil(1_193_182));
                ecb.put(m, 8, 0xfd);
                state.pending.push(request);
                al(regs, SUCCESS);
                return;
            }
            if !state.sockets.iter().any(|s| s.number == socket) {
                state.finish(m, request, FAILURE);
                al(regs, FAILURE);
                return;
            }
            let Some(buffers) = fragments(m, ecb) else {
                state.finish(m, request, MALFORMED);
                al(regs, FAILURE);
                return;
            };
            if regs.rbx as u16 == 4 {
                ecb.put(m, 8, 0xfe);
                state.pending.push(request);
                al(regs, SUCCESS);
                return;
            }
            let mut packet = Vec::new();
            for (source, len) in buffers {
                let start = packet.len();
                packet.resize(start + len, 0);
                m.copy_from(source.linear(), &mut packet[start..]);
            }
            if packet.len() < HEADER {
                state.finish(m, request, MALFORMED);
                al(regs, FAILURE);
                return;
            }
            let len = packet.len() as u16;
            packet[..2].fill(0xff);
            packet[2..4].copy_from_slice(&len.to_be_bytes());
            packet[4] = 0;
            packet[18..28].copy_from_slice(&state.address.unwrap());
            packet[28..30].copy_from_slice(&socket.to_be_bytes());
            let success = lan::send(
                state.session.unwrap(),
                packet[10..16].try_into().unwrap(),
                &packet,
            );
            state.finish(m, request, if success { SUCCESS } else { FAILURE });
            al(regs, if success { SUCCESS } else { FAILURE });
        }
        8 => {
            regs.rax = (regs.rax & !0xffff) | super::Bda::tick_count(m) as u16 as u64;
        }
        9 => {
            if ecb.valid(10) {
                m.copy_to(ecb.linear(), &state.address.unwrap());
            } else {
                al(regs, FAILURE);
            }
        }
        0x0a | 0x0b => {}
        0x0d | 0x1a => {
            regs.rax = (regs.rax & !0xffff) | MAX_PACKET as u64;
            regs.rcx &= !0xffff;
        }
        0x10 => al(regs, 0), // SPX not installed.
        _ => al(regs, FAILURE),
    }
}

pub(crate) fn deliver_callback<A: Arch>(m: &mut A, dos: &mut DosState<A>, regs: &mut Regs) -> bool {
    if dos.ipx.saved.is_some() || machine::guest_flags(regs) & machine::IF_FLAG == 0 {
        return false;
    }
    let Some(done) = dos.ipx.completed.pop_front() else {
        return false;
    };
    let dest = mode_transitions::rm_stack(dos, regs);
    mode_transitions::enter_rm(dos, regs, dest, None);
    dos.ipx.saved = Some([
        regs.rax, regs.rbx, regs.rcx, regs.rdx, regs.rsi, regs.rdi, regs.rbp,
    ]);
    machine::vm86_push(m, regs, super::dos::CTRL_STUB_SEG);
    machine::vm86_push(
        m,
        regs,
        super::dos::ctrl_slot_off(super::dos::SLOT_IPX_RETURN),
    );
    regs.rsi = (regs.rsi & !0xffff) | done.ecb.offset as u64;
    regs.es = done.ecb.segment as u64;
    al(regs, if done.event { 0 } else { 0xff });
    machine::set_vm86_cs(regs, done.esr.segment);
    machine::set_vm86_ip(regs, done.esr.offset);
    true
}
pub(crate) fn callback_return<A: Arch>(m: &mut A, dos: &mut DosState<A>, regs: &mut Regs) {
    for _ in 0..3 {
        let _ = machine::vm86_pop(m, regs);
    }
    let [ax, bx, cx, dx, si, di, bp] = dos.ipx.saved.take().expect("IPX callback return");
    regs.rax = ax;
    regs.rbx = bx;
    regs.rcx = cx;
    regs.rdx = dx;
    regs.rsi = si;
    regs.rdi = di;
    regs.rbp = bp;
    mode_transitions::resume_continuation_from_stub(m, dos, regs);
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    #[test]
    fn packet_lengths_are_bounded_and_exact() {
        let mut p = vec![0; HEADER];
        p[2..4].copy_from_slice(&(HEADER as u16).to_be_bytes());
        assert!(valid_packet(&p));
        p.push(0);
        assert!(!valid_packet(&p));
        assert!(!valid_packet(&vec![0; MAX_PACKET + 1]));
        assert!(!valid_packet(&[0; 29]));
    }
    #[test]
    fn buffers_cannot_wrap_or_reach_video_and_rom() {
        assert!(
            Far {
                segment: 0x1000,
                offset: 0xfff0
            }
            .valid(16)
        );
        assert!(
            !Far {
                segment: 0x1000,
                offset: 0xfff0
            }
            .valid(17)
        );
        assert!(
            !Far {
                segment: 0x9fff,
                offset: 0
            }
            .valid(17)
        );
        assert!(
            !Far {
                segment: 0xffff,
                offset: 0xffff
            }
            .valid(1)
        );
    }
}
