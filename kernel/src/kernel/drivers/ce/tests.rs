use super::*;
use alloc::{collections::BTreeMap, rc::Rc, vec};
use core::cell::RefCell;
#[derive(Clone)]
struct Ram(Rc<RefCell<Vec<u8>>>);
impl Memory for Ram {
    fn physical(&self) -> u64 {
        0x100000
    }
    fn read32(&self, at: usize) -> u32 {
        u32::from_le_bytes(self.0.borrow()[at..at + 4].try_into().unwrap())
    }
    fn write32(&mut self, at: usize, value: u32) {
        self.0.borrow_mut()[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn copy_in(&mut self, at: usize, bytes: &[u8]) {
        self.0.borrow_mut()[at..at + bytes.len()].copy_from_slice(bytes);
    }
    fn copy_out(&self, at: usize, count: usize) -> Vec<u8> {
        self.0.borrow()[at..at + count].to_vec()
    }
}
#[derive(Default)]
struct Io(BTreeMap<u32, u32>);
impl Registers for Io {
    fn read(&mut self, at: u32) -> Result<u32> {
        Ok(*self.0.get(&at).unwrap_or(&0))
    }
    fn write(&mut self, at: u32, value: u32) -> Result<()> {
        self.0.insert(at, value);
        Ok(())
    }
    fn now(&mut self) -> u64 {
        0
    }
}
const CONFIG: Config = Config {
    base: 0x1b80000,
    stride: 0x2000,
    pipes: &[
        Pipe {
            tx: 4,
            rx: 0,
            buffer_bytes: 32,
        },
        Pipe {
            tx: 0,
            rx: 4,
            buffer_bytes: 32,
        },
    ],
    target: &[],
    services: &[],
    control_receive: &[1],
};
fn engine() -> (Engine<Ram>, Ram, Io) {
    let bytes = Engine::<Ram>::required_bytes(CONFIG).unwrap();
    let memory = Ram(Rc::new(RefCell::new(vec![0; bytes])));
    let mut engine = Engine::new(CONFIG, memory.clone(), bytes).unwrap();
    let mut io = Io::default();
    engine.start(&mut io).unwrap();
    (engine, memory, io)
}
#[test]
fn ring_programming_uses_dword_sizes_and_separate_dma_pointer_writebacks() {
    let (engine, _, io) = engine();
    let tx = engine.queues[0].tx.as_ref().unwrap();
    assert_eq!(io.0[&(CONFIG.base + 4)], 16 << 8);
    assert_eq!(io.0[&(CONFIG.base + 8)], 4);
    assert_eq!(io.0[&(CONFIG.base + 0x10)], 0x42);
    assert_eq!(
        io.0[&(CONFIG.base + 0x1c)],
        0x100000 + tx.ring.shadow as u32
    );
    let rx = engine.queues[1].rx.as_ref().unwrap();
    assert_eq!(io.0[&(rx.post.r0 + 4)], 8 << 8);
    assert_eq!(io.0[&(rx.status.r0 + 8)], 4 | (101 << 8));
    assert_eq!(io.0[&(rx.status.r0 + 0x10)], 0x40);
    assert_eq!(
        io.0[&(rx.status.r0 + 0x14)],
        0x100000 + rx.status.shadow as u32
    );
    assert_eq!(io.0[&rx.post.r2], 4); // two initial buffers, two dwords per descriptor
    assert_eq!(rx.outstanding, 2);
    assert_ne!(tx.ring.shadow, rx.status.shadow);
    assert_eq!(io.0[&(rx.post.r0 + 0xb0)] & 0xffff, 32);
}
#[test]
fn tx_ownership_waits_for_hardware_tail_and_wraps_without_overwrite() {
    let (mut engine, mut memory, mut io) = engine();
    for value in 0..3 {
        engine.send(&mut io, 0, &[value; 8]).unwrap();
    }
    assert_eq!(engine.send(&mut io, 0, b"full"), Err(Error::Full));
    let shadow = engine.queues[0].tx.as_ref().unwrap().ring.shadow;
    memory.write32(shadow, 4); // hardware completed first entry
    engine.send(&mut io, 0, b"wrap").unwrap();
    assert_eq!(io.0[&(CONFIG.base + 0x400)], 0);
    assert_eq!(engine.send(&mut io, 0, b"full"), Err(Error::Full));
    memory.write32(shadow, 8);
    engine.send(&mut io, 0, b"reuse").unwrap();
    let tx = engine.queues[0].tx.as_ref().unwrap();
    assert_eq!(memory.read32(tx.ring.offset + 4), 5 << 16);
    assert_eq!(memory.copy_out(tx.buffers, 5), b"reuse");
    assert_eq!(engine.send(&mut io, 0, &[0; 33]), Err(Error::Packet));
}
#[test]
fn crash_snapshot_preserves_dma_bytes_without_reinitializing_queues() {
    let (mut engine, mut memory, mut io) = engine();
    engine.send(&mut io, 0, b"initialization packet").unwrap();
    let registers = io.0.clone();
    let (physical, snapshot) = engine.snapshot();
    let tx = engine.queues[0].tx.as_ref().unwrap();
    assert_eq!(physical, memory.physical());
    assert_eq!(
        snapshot.len(),
        Engine::<Ram>::required_bytes(CONFIG).unwrap()
    );
    assert_eq!(
        &snapshot[tx.buffers..tx.buffers + 21],
        b"initialization packet"
    );
    assert_eq!(
        u32::from_le_bytes(
            snapshot[tx.ring.offset + 4..tx.ring.offset + 8]
                .try_into()
                .unwrap()
        ),
        21 << 16
    );
    memory.copy_in(tx.buffers, b"overwritten");
    assert_eq!(
        &snapshot[tx.buffers..tx.buffers + 21],
        b"initialization packet"
    );
    assert_eq!(io.0, registers);
}
#[test]
fn receive_buffers_and_statuses_recycle_across_many_wraps() {
    let (mut engine, mut memory, mut io) = engine();
    for packet in 0..32usize {
        let rx = engine.queues[1].rx.as_ref().unwrap();
        memory.copy_in(rx.buffers + packet % 4 * 32, &[packet as u8; 12]);
        memory.write32(rx.status.offset + packet % 4 * 16, 12 << 16);
        memory.write32(rx.status.shadow, (((packet + 1) % 4) * 4) as u32);
        memory.write32(rx.post.shadow, (((packet + 1) % 4) * 2) as u32);
        engine.poll(&mut io).unwrap();
        assert_eq!(engine.receive().unwrap(), (1, vec![packet as u8; 12]));
        assert!(engine.receive().is_none());
        assert_eq!(engine.queues[1].rx.as_ref().unwrap().outstanding, 2);
    }
}
#[test]
fn malformed_dma_pointers_lengths_and_profiles_are_rejected() {
    for (pointer, length) in [(3, 8), (16, 8), (4, 0), (4, 33)] {
        let (mut engine, mut memory, mut io) = engine();
        let rx = engine.queues[1].rx.as_ref().unwrap();
        memory.write32(rx.status.shadow, pointer);
        memory.write32(rx.status.offset, length << 16);
        assert!(engine.poll(&mut io).is_err());
        assert!(engine.receive().is_none());
    }
    for config in [
        Config {
            stride: 0,
            ..CONFIG
        },
        Config {
            base: u32::MAX,
            ..CONFIG
        },
        Config {
            pipes: &[Pipe {
                tx: 3,
                rx: 0,
                buffer_bytes: 32,
            }],
            ..CONFIG
        },
    ] {
        assert!(Engine::<Ram>::required_bytes(config).is_err());
    }
    let memory = Ram(Rc::new(RefCell::new(vec![0; 8192])));
    assert!(Engine::new(CONFIG, memory, 1).is_err());
}
