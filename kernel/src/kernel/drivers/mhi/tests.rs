use super::*;
use alloc::{collections::BTreeMap, rc::Rc, vec};
use core::cell::RefCell;

#[test]
fn crash_dump_vectors_cover_short_final_segment_and_require_completion() {
    let bytes = SEGMENT + 16;
    let capacity = dump::CrashDump::<Ram>::required_bytes(bytes).unwrap();
    let mut memory = Ram::new(capacity, 0x100000);
    let mut capture = dump::CrashDump::new(memory.clone(), capacity, bytes).unwrap();
    assert_eq!(memory.read64(0), 0x101000);
    assert_eq!(memory.read64(8), SEGMENT as u64);
    assert_eq!(memory.read64(16), 0x101000 + SEGMENT as u64);
    assert_eq!(memory.read64(24), 16);
    let mut io = Fake::new();
    let layout = Layout::read(&mut io, 0x2000).unwrap();
    capture.arm(&mut io, layout).unwrap();
    assert_eq!(io.words[&(layout.bhie + 0x60)], 0x100000);
    assert_eq!(io.words[&(layout.bhie + 0x68)], 32);
    assert_eq!(io.words[&(layout.bhie + 0x70)], 3);
    assert_eq!(capture.collect(&mut io, layout).unwrap(), None); // healthy device
    assert!(capture.arm(&mut io, layout).is_err());
    memory.copy_in(4096, b"crash bytes");
    memory.copy_in(4096 + bytes - 4, b"tail");
    io.words.insert(layout.bhi + 0x28, 3);
    io.words.insert(layout.bhie + 0x78, 2 << 30);
    let result = capture.collect(&mut io, layout).unwrap().unwrap();
    assert_eq!(result.len(), bytes);
    assert_eq!(&result[..11], b"crash bytes");
    assert_eq!(&result[bytes - 4..], b"tail");
    assert_eq!(capture.collect(&mut io, layout).unwrap(), None); // consume once
    assert!(capture.arm(&mut io, layout).is_err()); // no stale completed transfer reuse
}

#[test]
fn crash_dump_rejects_invalid_storage_and_failed_or_incomplete_dma() {
    assert!(dump::CrashDump::<Ram>::required_bytes(0).is_err());
    assert!(dump::CrashDump::<Ram>::required_bytes(usize::MAX).is_err());
    assert!(dump::CrashDump::new(Ram::new(8192, 0x100001), 8192, 16).is_err());
    assert!(dump::CrashDump::new(Ram::new(4096, 0x100000), 4096, 16).is_err());
    for (status, expected) in [(3 << 30 | 3, Error::Firmware), (3, Error::Timeout)] {
        let mut io = Fake::new();
        let layout = Layout::read(&mut io, 0x2000).unwrap();
        let mut capture = dump::CrashDump::new(Ram::new(8192, 0x100000), 8192, 16).unwrap();
        capture.arm(&mut io, layout).unwrap();
        io.words.insert(layout.bhi + 0x28, 3);
        io.words.insert(layout.bhie + 0x78, status);
        assert_eq!(capture.collect(&mut io, layout), Err(expected));
    }
}

#[derive(Clone)]
struct Ram {
    words: Rc<RefCell<Vec<u8>>>,
    base: u64,
}
impl Ram {
    fn new(bytes: usize, base: u64) -> Self {
        Self {
            words: Rc::new(RefCell::new(vec![0; bytes])),
            base,
        }
    }
}
impl Memory for Ram {
    fn physical(&self) -> u64 {
        self.base
    }
    fn read32(&self, offset: usize) -> u32 {
        u32::from_le_bytes(self.words.borrow()[offset..offset + 4].try_into().unwrap())
    }
    fn write32(&mut self, offset: usize, value: u32) {
        self.words.borrow_mut()[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn copy_in(&mut self, offset: usize, bytes: &[u8]) {
        self.words.borrow_mut()[offset..offset + bytes.len()].copy_from_slice(bytes);
    }
    fn copy_out(&self, offset: usize, count: usize) -> Vec<u8> {
        self.words.borrow()[offset..offset + count].to_vec()
    }
}

struct Fake {
    words: BTreeMap<u32, u32>,
    time: u64,
    fail_bhi: bool,
    fail_bhie: bool,
    stuck: bool,
    memory: Option<Ram>,
    auto_command: bool,
    required_credit: Option<u32>,
    ignored_commands: usize,
}
impl Fake {
    fn new() -> Self {
        Self {
            words: BTreeMap::from([(0x28, 0x100), (0x2c, 0x200), (0x18, 0x1000), (0x20, 0x1800)]),
            time: 0,
            fail_bhi: false,
            fail_bhie: false,
            stuck: false,
            memory: None,
            auto_command: true,
            required_credit: None,
            ignored_commands: 0,
        }
    }
    fn event(&mut self, pointer: u64, data: u32, kind: u32) {
        let memory = self.memory.as_mut().unwrap();
        let produced = ring_index(
            memory.read64(EVENT_CONTEXT + 28),
            memory.physical() + EVENTS[0] as u64,
            32,
        )
        .unwrap();
        let offset = EVENTS[0] + produced * 16;
        memory.write64(offset, pointer);
        memory.write32(offset + 8, data);
        memory.write32(offset + 12, kind);
        memory.write64(
            EVENT_CONTEXT + 28,
            memory.physical() + (EVENTS[0] + ((produced + 1) % 32) * 16) as u64,
        );
    }
}
impl Registers for Fake {
    fn read(&mut self, offset: u32) -> Result<u32> {
        Ok(*self.words.get(&offset).unwrap_or(&0))
    }
    fn write(&mut self, offset: u32, value: u32) -> Result<()> {
        self.words.insert(offset, value);
        if self.stuck {
            return Ok(());
        }
        if offset == 0x118 {
            self.words
                .insert(0x12c, (if self.fail_bhi { 3 } else { 2 }) << 30);
            self.words.insert(0x128, 1);
            self.words.insert(STATUS, 1);
        }
        if offset == CTRL && value == 2 << 8 {
            self.words.insert(STATUS, (2 << 8) | 1);
        }
        if offset == 0x23c {
            self.words
                .insert(0x244, (if self.fail_bhie { 3 } else { 2 }) << 30);
            self.words.insert(0x128, 2);
            // Mission firmware has not observed the bootloader's doorbells.
            for er in 0..2 {
                self.words.remove(&(0x1800 + er * 8));
            }
        }
        if offset == 0x70 && self.auto_command && self.memory.is_some() {
            let memory = self.memory.as_ref().unwrap();
            if let Some(required) = self.required_credit {
                if memory.read64(EVENT_CONTEXT + 36) as u32 != required {
                    self.ignored_commands += 1;
                    return Ok(());
                }
                self.required_credit = None;
            }
            let base = memory.read64(COMMAND_CONTEXT + 12);
            let len = memory.read64(COMMAND_CONTEXT + 20);
            if len == 0 || !base.is_multiple_of(len) {
                return Ok(());
            }
            for er in 0..2 {
                let credit = memory.read64(EVENT_CONTEXT + er * CHANNEL_CONTEXT + 36) as u32;
                if self.words.get(&(0x1800 + er as u32 * 8)) != Some(&credit) {
                    return Ok(());
                }
            }
            let next = ((u64::from(value) - memory.physical() - COMMAND_RING as u64) / 16) as usize;
            let slot = (next + 127) % 128;
            let pointer = memory.physical() + (COMMAND_RING + slot * 16) as u64;
            self.event(pointer, 1 << 24, 0x21 << 16);
        }
        Ok(())
    }
    fn now(&mut self) -> u64 {
        self.time += 1_000_000;
        self.time
    }
}

#[test]
fn firmware_boot_publishes_contexts_and_reaches_amss() {
    let mut io = Fake::new();
    let layout = Layout::read(&mut io, 0x10000).unwrap();
    let mut contexts = Ram::new(CONTEXT_BYTES, 0x100000);
    boot(
        &mut io,
        &mut contexts,
        layout,
        Channels::new(20, 21).unwrap(),
        Firmware {
            first_stage: 0x200000,
            first_bytes: SEGMENT,
            vectors: 0x400000,
            vector_bytes: 48,
        },
    )
    .unwrap();
    assert_eq!(io.words[&0x128], 2);
    assert_eq!(io.words[&0x58], 0x100000);
    assert_eq!(io.words[&0x60], 0x102000);
    assert_eq!(io.words[&0x10] >> 16, 2);
    assert_eq!(io.words[&0x234], 48);
    assert_eq!(contexts.read32(21 * 44 + 4), 2);
    assert_eq!(contexts.read64(EVENT_CONTEXT + 36), 0x1051f0);
}

#[test]
fn transfer_errors_and_timeouts_do_not_report_boot_success() {
    for mode in 0..3 {
        let mut io = Fake::new();
        io.fail_bhi = mode == 0;
        io.fail_bhie = mode == 1;
        io.stuck = mode == 2;
        let layout = Layout::read(&mut io, 0x10000).unwrap();
        let mut memory = Ram::new(CONTEXT_BYTES, 0x100000);
        assert_eq!(
            boot(
                &mut io,
                &mut memory,
                layout,
                Channels::new(20, 21).unwrap(),
                Firmware {
                    first_stage: 0x200000,
                    first_bytes: SEGMENT,
                    vectors: 0x400000,
                    vector_bytes: 16
                }
            ),
            Err(if mode == 2 {
                Error::Timeout
            } else {
                Error::Firmware
            })
        );
    }
}

#[test]
fn register_layout_and_device_pointers_are_bounded() {
    let mut io = Fake::new();
    for offset in [0, 3, u32::MAX, 0xfffc] {
        io.words.insert(0x18, offset);
        assert!(Layout::read(&mut io, 0x10000).is_err());
    }
    assert_eq!(ring_index(0x1000, 0x1000, 32), Ok(0));
    assert_eq!(ring_index(0x11f0, 0x1000, 32), Ok(31));
    for pointer in [0, 0xff0, 0x1001, 0x1200, u64::MAX] {
        assert_eq!(ring_index(pointer, 0x1000, 32), Err(Error::Pointer));
    }
}

fn transport() -> Transport<Fake, Ram> {
    transport_with(Channels::new(20, 21).unwrap())
}

fn transport_with(channels: Channels) -> Transport<Fake, Ram> {
    let mut io = Fake::new();
    let layout = Layout::read(&mut io, 0x10000).unwrap();
    let mut memory = Ram::new(CONTEXT_BYTES, 0x100000);
    initialize_contexts(&mut memory, channels).unwrap();
    io.words.insert(STATUS, (2 << 8) | 1);
    io.memory = Some(memory.clone());
    let mut transport = Transport::new(
        io,
        memory,
        Ram::new(PACKET_STORAGE, 0x200000),
        layout,
        channels,
    );
    transport.start().unwrap();
    transport
}

#[test]
fn channel_commands_receive_recycling_and_tx_backpressure() {
    let mut transport = transport();
    assert_eq!(transport.rx_write, 63);
    for _ in 0..63 {
        transport.send(b"QRTR").unwrap();
    }
    assert_eq!(transport.send(b"full"), Err(Error::Full));
    let pointer = transport.contexts.physical() + TRANSFERS[0] as u64;
    transport
        .io
        .event(pointer, (2 << 24) | 4, (20 << 24) | (0x22 << 16));
    transport.poll().unwrap();
    transport.send(b"wrapped").unwrap();
    for index in 0..256 {
        let slot = index % 64;
        transport
            .packets
            .copy_in((DEPTH + slot) * PACKET_BYTES, b"firmware response");
        let pointer = transport.contexts.physical() + (TRANSFERS[1] + slot * 16) as u64;
        transport
            .io
            .event(pointer, (2 << 24) | 17, (21 << 24) | (0x22 << 16));
        transport.poll().unwrap();
        assert_eq!(transport.receive().unwrap(), b"firmware response");
    }
}

#[test]
fn corrupt_completions_cannot_read_or_reuse_arbitrary_dma() {
    for (pointer, data, kind) in [
        (u64::MAX, (2 << 24) | 8, (21 << 24) | (0x22 << 16)),
        (0x108000, (2 << 24) | 8193, (21 << 24) | (0x22 << 16)),
        (0x108010, (2 << 24) | 8, (21 << 24) | (0x22 << 16)),
        (0x107000, (2 << 24) | 8, (20 << 24) | (0x22 << 16)),
        (0x102400, 1 << 24, 0x21 << 16),
    ] {
        let mut transport = transport();
        transport.io.event(pointer, data, kind);
        assert!(transport.poll().is_err());
        assert!(transport.receive().is_none());
    }
}

#[test]
fn configured_non_adjacent_channels_drive_contexts_doorbells_and_completions() {
    let mut transport = transport_with(Channels::new(4, 9).unwrap());
    assert_eq!(transport.contexts.read32(4 * CHANNEL_CONTEXT + 4), 1);
    assert_eq!(transport.contexts.read32(9 * CHANNEL_CONTEXT + 4), 2);
    assert_eq!(transport.contexts.read32(20 * CHANNEL_CONTEXT + 4), 0);
    transport.send(b"shared").unwrap();
    assert_eq!(
        transport.io.words[&(transport.layout.channel_db + 4 * 8)],
        0x107010
    );
    assert_eq!(
        transport.io.words[&(transport.layout.channel_db + 9 * 8)],
        0x1083f0
    );
    transport
        .io
        .event(0x107000, (2 << 24) | 6, (4 << 24) | (0x22 << 16));
    transport.packets.copy_in(DEPTH * PACKET_BYTES, b"reply");
    transport
        .io
        .event(0x108000, (2 << 24) | 5, (9 << 24) | (0x22 << 16));
    transport.poll().unwrap();
    assert_eq!(transport.receive().unwrap(), b"reply");
    assert_eq!(transport.tx_read, 1);
    // A completion for the previous chipset's channel is not accepted.
    transport
        .io
        .event(0x108010, (2 << 24) | 5, (21 << 24) | (0x22 << 16));
    assert_eq!(transport.poll(), Err(Error::Completion));
}

#[test]
fn channel_configuration_rejects_aliasing_and_the_wake_channel() {
    for pair in [(4, 4), (0, 127), (127, 0), (255, 1)] {
        assert!(Channels::new(pair.0, pair.1).is_none());
    }
    assert!(Channels::new(0, 126).is_some());
}

#[test]
fn context_arrays_and_rings_have_separate_pages() {
    let mut memory = Ram::new(CONTEXT_BYTES, 0x101000);
    initialize_contexts(&mut memory, Channels::new(20, 21).unwrap()).unwrap();
    let mut ranges = vec![
        (
            memory.physical(),
            memory.physical() + (128 * CHANNEL_CONTEXT) as u64,
        ),
        (
            memory.physical() + EVENT_CONTEXT as u64,
            memory.physical() + (EVENT_CONTEXT + 2 * CHANNEL_CONTEXT) as u64,
        ),
        (
            memory.physical() + COMMAND_CONTEXT as u64,
            memory.physical() + (COMMAND_CONTEXT + CHANNEL_CONTEXT) as u64,
        ),
    ];
    assert!(ranges.iter().all(|(base, _)| base.is_multiple_of(4096)));
    for offset in [
        COMMAND_CONTEXT,
        EVENT_CONTEXT,
        EVENT_CONTEXT + CHANNEL_CONTEXT,
        20 * CHANNEL_CONTEXT,
        21 * CHANNEL_CONTEXT,
    ] {
        let base = memory.read64(offset + 12);
        let len = memory.read64(offset + 20);
        assert!(base.is_multiple_of(len));
        assert!(base.is_multiple_of(4096));
        assert!(base >= memory.physical());
        assert!(base + len <= memory.physical() + CONTEXT_BYTES as u64);
        ranges.push((base, base + len));
    }
    ranges.sort();
    assert!(
        ranges
            .windows(2)
            .all(|pair| pair[0].1.div_ceil(4096) * 4096 <= pair[1].0)
    );
}

#[test]
fn invalid_context_addresses_are_rejected_before_writing_them() {
    for base in [0x100800, 0x100100, 1u64 << 32, u64::MAX - 4096] {
        let mut memory = Ram::new(CONTEXT_BYTES, base);
        assert_eq!(
            initialize_contexts(&mut memory, Channels::new(20, 21).unwrap()),
            Err(Error::Pointer)
        );
        assert!(memory.words.borrow().iter().all(|byte| *byte == 0));
    }
}

#[test]
fn mission_firmware_gets_fresh_event_credits_before_commands() {
    let mut io = Fake::new();
    let layout = Layout::read(&mut io, 0x10000).unwrap();
    let channels = Channels::new(20, 21).unwrap();
    let mut memory = Ram::new(CONTEXT_BYTES, 0x100000);
    boot(
        &mut io,
        &mut memory,
        layout,
        channels,
        Firmware {
            first_stage: 0x200000,
            first_bytes: SEGMENT,
            vectors: 0x400000,
            vector_bytes: 16,
        },
    )
    .unwrap();
    assert!(!io.words.contains_key(&layout.event_db));
    io.memory = Some(memory.clone());
    let mut transport = Transport::new(
        io,
        memory,
        Ram::new(PACKET_STORAGE, 0x200000),
        layout,
        channels,
    );
    transport.start().unwrap();
    assert!(transport.io.words.contains_key(&layout.event_db));
    assert!(transport.command_done);
}

#[test]
fn resume_republishes_outstanding_transfers() {
    let mut transport = transport();
    transport.send(b"pending").unwrap();
    let tx_db = transport.layout.channel_db + 20 * 8;
    let rx_db = transport.layout.channel_db + 21 * 8;
    transport.io.words.remove(&tx_db);
    transport.io.words.remove(&rx_db);
    transport.io.words.remove(&transport.layout.event_db);
    transport.io.words.insert(STATUS, (4 << 8) | 1);
    transport.poll().unwrap();
    assert_eq!(transport.io.words[&STATUS] >> 8, 2);
    assert_eq!(
        transport.io.words[&tx_db],
        transport.contexts.read64(20 * CHANNEL_CONTEXT + 36) as u32
    );
    assert_eq!(
        transport.io.words[&rx_db],
        transport.contexts.read64(21 * CHANNEL_CONTEXT + 36) as u32
    );
    assert!(transport.io.words.contains_key(&transport.layout.event_db));
}

#[test]
fn missing_command_completion_times_out_without_starting_receive_dma() {
    let mut io = Fake::new();
    let layout = Layout::read(&mut io, 0x10000).unwrap();
    let channels = Channels::new(20, 21).unwrap();
    let mut memory = Ram::new(CONTEXT_BYTES, 0x100000);
    initialize_contexts(&mut memory, channels).unwrap();
    io.memory = Some(memory.clone());
    io.words.insert(STATUS, (2 << 8) | 1);
    io.auto_command = false;
    let mut transport = Transport::new(
        io,
        memory,
        Ram::new(PACKET_STORAGE, 0x200000),
        layout,
        channels,
    );
    assert_eq!(transport.start(), Err(Error::Timeout));
    assert_eq!(transport.pending_command, Some((0x104000, 20)));
    assert_eq!(transport.rx_write, 0);
    transport.log_state();
    assert!(!transport.command_done);
}

#[test]
fn startup_acknowledges_mission_events_before_issuing_commands() {
    let mut io = Fake::new();
    let layout = Layout::read(&mut io, 0x10000).unwrap();
    let channels = Channels::new(20, 21).unwrap();
    let mut memory = Ram::new(CONTEXT_BYTES, 0x100000);
    initialize_contexts(&mut memory, channels).unwrap();
    io.memory = Some(memory.clone());
    io.words.insert(STATUS, (2 << 8) | 1);
    io.event(0, 2 << 24, 0x20 << 16);
    io.event(0, 2 << 24, 0x40 << 16);
    io.required_credit = Some((memory.physical() + EVENTS[0] as u64 + 16) as u32);
    let mut transport = Transport::new(
        io,
        memory,
        Ram::new(PACKET_STORAGE, 0x200000),
        layout,
        channels,
    );
    transport.start().unwrap();
    assert_eq!(transport.io.ignored_commands, 0);
    assert!(transport.command_done);
}

#[test]
fn m0_event_replays_pending_command_even_if_status_already_says_m0() {
    let mut transport = transport();
    let slot = transport.command_write;
    let offset = COMMAND_RING + slot * 16;
    transport.contexts.write64(offset, 0);
    transport.contexts.write32(offset + 8, 0);
    transport.contexts.write32(offset + 12, 1 << 16); // NOP
    let pointer = transport.contexts.physical() + offset as u64;
    transport.pending_command = Some((pointer, 0));
    transport.command_done = false;
    transport.command_write = (slot + 1) % 128;
    transport
        .contexts
        .write64(COMMAND_CONTEXT + 36, pointer + 16);
    transport.io.words.remove(&0x70); // notification lost during transition
    transport.io.event(0, 2 << 24, 0x20 << 16);
    transport.poll().unwrap();
    assert_eq!(transport.io.words[&0x70], (pointer + 16) as u32);
    transport.poll().unwrap();
    assert!(transport.command_done);
    assert!(transport.pending_command.is_none());
}
