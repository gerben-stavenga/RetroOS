use super::*;
use alloc::{collections::BTreeMap, rc::Rc, vec};
use core::cell::RefCell;
#[derive(Clone)]
pub(super) struct Ram(pub(super) Rc<RefCell<Vec<u8>>>);
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
    fn copy_out(&self, at: usize, len: usize) -> Vec<u8> {
        self.0.borrow()[at..at + len].to_vec()
    }
}
#[derive(Default)]
pub(super) struct Io(pub(super) BTreeMap<u32, u32>);
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
fn config() -> Config {
    Config {
        idle_r0: 0xa34d3c,
        idle_r2: 0xa370b8,
        reo_r0: 0xa384e4,
        reo_r2: 0xa3b048,
        link_entries: 4,
        reo_entries: 4,
        reo_count: 2,
        common: &[],
        reo_setup: None,
    }
}

#[test]
fn common_rings_have_disjoint_dma_and_commands_stay_unpublished() {
    let cfg = Config {
        common: &[
            RingConfig {
                r0: 0xa3828c,
                r2: 0xa3b020,
                id: 20,
                entries: 128,
                words: 12,
                destination: false,
                command_numbers: true,
            },
            RingConfig {
                r0: 0xa38a84,
                r2: 0xa3b0a8,
                id: 21,
                entries: 2048,
                words: 28,
                destination: true,
                command_numbers: false,
            },
        ],
        reo_count: 4,
        reo_setup: Some(ReoConfig {
            base: 0xa38000,
            misc: 0xa38b7c,
            aging: 0xa38b08,
        }),
        ..config()
    };
    let bytes = Bootstrap::<Ram>::required_bytes(cfg).unwrap();
    let memory = Ram(Rc::new(RefCell::new(vec![0; bytes])));
    let mut dp = Bootstrap::new(cfg, memory.clone(), bytes).unwrap();
    let mut io = Io::default();
    io.0.insert(0xa38000, 0x100);
    io.0.insert(0xa38b7c, 0xffffffff);
    dp.start(&mut io).unwrap();
    // Every initialized hardware ring owns a separate descriptor span and
    // writeback slot. Data/command queues have no published descriptors.
    let mut end = 0;
    let mut shadows = Vec::new();
    for ring in core::iter::once(&dp.idle).chain(&dp.reo).chain(&dp.common) {
        assert!(ring.offset >= end);
        end = ring.offset + ring.entries * ring.words * 4;
        assert!(end <= bytes);
        assert!(!shadows.contains(&ring.shadow));
        shadows.push(ring.shadow);
    }
    for (ring, spec) in dp.common.iter().zip(cfg.common) {
        assert_eq!(io.0[&ring.r2], 0);
        assert_eq!(io.0[&(ring.r2 + 4)], 0);
        assert_eq!(
            io.0[&(ring.r0 + 4)],
            (spec.entries * spec.words * 256) as u32
        );
        assert_eq!(
            io.0[&(ring.r0 + 0x10)],
            if spec.destination { 0x40 } else { 0x42 }
        );
        if spec.command_numbers {
            for index in 0..ring.entries {
                assert_eq!(
                    memory.read32(ring.offset + index * 48 + 8),
                    index as u32 + 1
                );
                assert_eq!(memory.read64(ring.offset + index * 48), 0);
            }
        }
    }
    assert_eq!(io.0[&0xa38000], 0x10c);
    assert_eq!(io.0[&0xa38b7c], 0xfe01ffff);
    assert_eq!(io.0[&0xa3800c], 0x43214321);
    assert_eq!(io.0[&0xa38010], 0x43214321);
    assert_eq!(io.0[&0xa38b08], 100000);
    assert_eq!(io.0[&0xa38b14], 40000);
    assert!(!io.0.contains_key(&cfg.reo_r0));
    dp.start_receive(&mut io).unwrap();
}
#[test]
fn hardware_pool_has_aligned_unique_links_and_empty_receive_destinations() {
    let cfg = config();
    let bytes = Bootstrap::<Ram>::required_bytes(cfg).unwrap();
    let memory = Ram(Rc::new(RefCell::new(vec![0; bytes])));
    let mut dp = Bootstrap::new(cfg, memory.clone(), bytes).unwrap();
    let mut io = Io::default();
    assert_eq!(dp.start_receive(&mut io), Err(Error::State));
    dp.start(&mut io).unwrap();
    dp.start_receive(&mut io).unwrap();
    assert_eq!(io.0[&(cfg.idle_r0 + 0x10)], 0x43);
    assert_eq!(io.0[&cfg.idle_r2], 6); // three posted entries, in DWORDs
    assert!(!io.0.contains_key(&(cfg.idle_r0 + 0x1c))); // idle links have no DMA tail
    let mut addresses = Vec::new();
    for index in 0..3 {
        let offset = 4096 + index * 8;
        let address = memory.read32(offset) as usize;
        assert!(address.is_multiple_of(128));
        assert!(!addresses.contains(&address));
        addresses.push(address);
        assert_eq!(memory.read32(offset + 4) & 0xf00, 0x100); // idle link buffer manager
        assert_eq!(memory.read32(offset + 4) >> 12 & 7, 0); // bank zero
        assert_eq!(memory.copy_out(address - 0x100000, 128), vec![0; 128]);
    }
    assert_eq!(memory.read64(4096 + 3 * 8), 0); // leave one empty slot
    for index in 0..2 {
        let r0 = cfg.reo_r0 + index * 0x78;
        let r2 = cfg.reo_r2 + index * 8;
        assert_eq!(io.0[&(r0 + 4)], 32 << 8); // four 8-DWORD entries
        assert_eq!(io.0[&(r0 + 8)], 8 | ((index + 1) << 8));
        assert_eq!(io.0[&(r0 + 0x10)], 0x40);
        assert_eq!(io.0[&r2], 0);
        assert_eq!(io.0[&(r2 + 4)], 0);
        assert_eq!(io.0[&(r0 + 0x14)], 0x100004 + index * 4);
    }
    assert_eq!(dp.start(&mut io), Err(Error::State));
    assert_eq!(dp.start_receive(&mut io), Err(Error::State));
}
#[test]
fn packet_engine_rejects_invalid_sizes_and_truncated_dma() {
    for cfg in [
        Config {
            link_entries: 0,
            ..config()
        },
        Config {
            link_entries: 32769,
            ..config()
        },
        Config {
            reo_count: 9,
            ..config()
        },
        Config {
            reo_entries: 3,
            ..config()
        },
        Config {
            idle_r0: u32::MAX,
            ..config()
        },
    ] {
        assert!(Bootstrap::<Ram>::required_bytes(cfg).is_err());
    }
    let bytes = Bootstrap::<Ram>::required_bytes(config()).unwrap();
    assert!(
        Bootstrap::new(
            config(),
            Ram(Rc::new(RefCell::new(vec![0; bytes]))),
            bytes - 1
        )
        .is_err()
    );
}
