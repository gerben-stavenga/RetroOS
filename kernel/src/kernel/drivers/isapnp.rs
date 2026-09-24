//! Minimal ISA Plug and Play support for activating Creative SB16 audio.
//!
//! Inspired by Linux's pnp_activate_dev / ISA PnP backend (Jaroslav Kysela,
//! Adam Belay and contributors):
//! https://github.com/torvalds/linux/blob/master/drivers/pnp/isapnp/core.c
//! https://github.com/torvalds/linux/blob/master/drivers/pnp/manager.c
//! This implements the ISA PnP register protocol, not Linux's resource allocator.
//! The caller supplies the physical resources; descriptor validation keeps a
//! request within one advertised dependent-resource alternative.
//!
//! PnP must assign IRQ/DMA as well as ports: Creative's Sound Blaster Series
//! Hardware Programming Guide, p. 2-11, specifies mixer 80h/81h as read-only
//! on PnP boards (https://www.phatcode.net/res/243/files/sbhwpg.pdf#page=29).
//! Setting only the DSP base and relying on legacy mixer restrapping would
//! leave those cards without the requested IRQ/DMA routing. After activation,
//! the ordinary SB16 DSP discovery and audio initialization are shared.

use alloc::vec::Vec;
use super::sb16::SbWiring;

const ADDRESS: u16 = 0x279;
const WRITE: u16 = 0xA79;
const READ_PORTS: &[u16] = &[0x213, 0x233, 0x253, 0x273, 0x393, 0x3B3, 0x3D3, 0x3F3];

#[derive(Clone, Copy, Debug)]
pub struct SbResources {
    pub base: u16,
    pub mpu: u16,
    pub wiring: SbWiring,
}

trait Io {
    fn out(&mut self, port: u16, value: u8);
    fn input(&mut self, port: u16) -> u8;
    fn delay(&mut self, us: u64);
}

struct Hardware<'a, A>(&'a mut A);
impl<A: crate::Arch> Io for Hardware<'_, A> {
    fn out(&mut self, port: u16, value: u8) { self.0.outb(port, value); }
    fn input(&mut self, port: u16) -> u8 { self.0.inb(port) }
    fn delay(&mut self, us: u64) {
        let end = crate::kernel::portio::now_ns().saturating_add(us * 1000);
        while crate::kernel::portio::now_ns() < end { core::hint::spin_loop(); }
    }
}

struct Bus<I> { io: I, rdp: u16 }
impl<I: Io> Bus<I> {
    fn address(&mut self, index: u8) { self.io.out(ADDRESS, index); self.io.delay(20); }
    fn write(&mut self, index: u8, value: u8) { self.address(index); self.io.out(WRITE, value); }
    fn read(&mut self, index: u8) -> u8 { self.address(index); self.io.input(self.rdp) }
    fn key(&mut self) {
        self.io.delay(1000);
        self.address(0); self.address(0);
        let mut key = 0x6A;
        for _ in 0..32 { self.address(key); key = lfsr(key, 0); }
    }
    fn wait(&mut self) { self.write(2, 2); }
    fn select(&mut self, csn: u8, ldn: u8) { self.write(3, csn); self.write(7, ldn); }
    fn isolate(&mut self) -> Vec<u8> {
        for &rdp in READ_PORTS {
            self.rdp = rdp;
            self.wait(); self.key();
            // Reset card numbers ONLY. Do not reset existing resource settings
            // or deactivate devices initialized by firmware / UNISOUND.
            self.write(2, 4); self.io.delay(2000);
            self.wait(); self.key();
            let mut cards = Vec::new();
            for csn in 1..=32 {
                self.write(3, 0);
                self.write(0, (rdp >> 2) as u8);
                self.io.delay(1000);
                self.address(1); self.io.delay(1000);
                let mut serial = [0u8; 9];
                for bit in 0..72 {
                    let high = self.io.input(rdp); self.io.delay(250);
                    let low = self.io.input(rdp); self.io.delay(250);
                    if (high, low) == (0x55, 0xAA) { serial[bit / 8] |= 1 << (bit % 8); }
                }
                if !valid_serial(&serial) { break; }
                self.write(6, csn); self.io.delay(250);
                cards.push(csn);
            }
            if !cards.is_empty() { return cards; }
        }
        Vec::new()
    }
    fn resource_byte(&mut self) -> Option<u8> {
        for _ in 0..20 {
            if self.read(5) & 1 != 0 { return Some(self.read(4)); }
            self.io.delay(100);
        }
        None
    }
    fn resource_stream(&mut self, csn: u8) -> Option<Vec<u8>> {
        self.write(3, csn);
        let mut serial = [0; 9];
        for byte in &mut serial { *byte = self.resource_byte()?; }
        if !valid_serial(&serial) { return None; }
        let mut bytes = Vec::new();
        while bytes.len() < 8192 {
            let tag = self.resource_byte()?;
            bytes.push(tag);
            let size = if tag & 0x80 != 0 {
                let lo = self.resource_byte()?; let hi = self.resource_byte()?;
                bytes.extend_from_slice(&[lo, hi]);
                usize::from(u16::from_le_bytes([lo, hi]))
            } else { usize::from(tag & 7) };
            if size > 8192 - bytes.len() { return None; }
            for _ in 0..size { bytes.push(self.resource_byte()?); }
            if tag >> 3 == 0x0F {
                // A zero checksum byte explicitly means "checksum omitted".
                if size != 1 || (*bytes.last()? != 0 && bytes.iter().fold(0u8, |a, b| a.wrapping_add(*b)) != 0) {
                    return None;
                }
                return Some(bytes);
            }
        }
        None
    }

    /// Preserve active PnP devices, including non-audio functions on the
    /// same card. Ten-bit ISA aliases are treated conservatively as conflicts.
    fn conflicts(&mut self, device: &Device, want: SbResources) -> bool {
        self.select(device.csn, device.ldn);
        if self.read(0x30) & 1 == 0 { return false; }
        for index in 0..2 {
            if self.read(0x70 + index * 2) == want.wiring.irq { return true; }
            let dma = self.read(0x74 + index);
            if dma == want.wiring.dma8 || Some(dma) == want.wiring.dma16 { return true; }
        }
        let len = device.resources.iter().filter_map(|(_, r)| match r {
            Resource::Port { len, .. } => Some(*len), _ => None,
        }).max().unwrap_or(1);
        for index in 0..8 {
            let port = u16::from_be_bytes([self.read(0x60 + index * 2), self.read(0x61 + index * 2)]);
            if port == 0 { continue; }
            for (base, size) in [(want.base, 16), (want.mpu, 2), (0x388, 4)] {
                if port_overlap(port, len, base, size) { return true; }
            }
        }
        false
    }

    /// Configure an inactive or firmware-initialized PnP audio device. Keep
    /// its original activation bit and resources for rollback, including when
    /// the subsequent DSP probe fails.
    fn activate(&mut self, device: &Device, registers: &[(u8, u8)]) -> Option<Snapshot> {
        self.select(device.csn, device.ldn);
        let old = Snapshot {
            active: self.read(0x30),
            registers: registers.iter().map(|&(r, _)| (r, self.read(r))).collect(),
        };
        if old.active & 1 != 0 && old.registers == registers { return Some(old); }
        self.write(0x30, 0); self.io.delay(500);
        for &(r, value) in registers { self.write(r, value); }
        if registers.iter().all(|&(r, v)| self.read(r) == v) {
            self.write(0x30, 1); self.io.delay(250);
            if self.read(0x30) & 1 != 0 { return Some(old); }
        }
        self.restore(device, &old);
        None
    }

    fn restore(&mut self, device: &Device, old: &Snapshot) {
        self.select(device.csn, device.ldn);
        self.write(0x30, 0); self.io.delay(500);
        for &(r, value) in &old.registers { self.write(r, value); }
        self.write(0x30, old.active); self.io.delay(250);
    }

}

fn port_overlap(a: u16, a_len: u8, b: u16, b_len: u8) -> bool {
    (0..u16::from(a_len)).any(|i| (0..u16::from(b_len))
        .any(|j| a.wrapping_add(i) & 0x3FF == b.wrapping_add(j) & 0x3FF))
}

fn lfsr(value: u8, bit: u8) -> u8 { (value >> 1) | (((value ^ (value >> 1) ^ bit) & 1) << 7) }
fn valid_serial(serial: &[u8; 9]) -> bool {
    let mut checksum = 0x6A;
    for bit in 0..64 { checksum = lfsr(checksum, (serial[bit / 8] >> (bit % 8)) & 1); }
    checksum != 0 && checksum == serial[8]
}

#[derive(Clone, Copy, Debug)]
enum Resource {
    Port { min: u16, max: u16, align: u8, len: u8 },
    Irq(u16, u8),
    Dma(u8),
    Unsupported,
}
struct Device { id: [u8; 4], csn: u8, ldn: u8, supported: bool, resources: Vec<(Option<usize>, Resource)>, alternatives: usize }

fn creative_audio(id: &[u8]) -> bool {
    // Compressed EISA manufacturer "CTL" plus logical audio IDs listed by
    // Linux's snd_sb16_pnpids. Gameport / IDE / wavetable devices are excluded.
    id.len() >= 4 && id[..2] == [0x0E, 0x8C]
        && matches!(u16::from_be_bytes([id[2], id[3]]),
            0x0001 | 0x0031 | 0x0041 | 0x0042 | 0x0043 | 0x0044 | 0x0045)
}

fn parse_devices(csn: u8, bytes: &[u8]) -> Option<Vec<Device>> {
    let mut result: Vec<Device> = Vec::new();
    let mut pos = 0;
    let mut alternative = None;
    let mut ended_group = false;
    while pos < bytes.len() {
        let tag = bytes[pos]; pos += 1;
        let (kind, size) = if tag & 0x80 != 0 {
            let size = u16::from_le_bytes(bytes.get(pos..pos + 2)?.try_into().ok()?);
            pos += 2;
            (tag, usize::from(size))
        } else { (tag >> 3, usize::from(tag & 7)) };
        let data = bytes.get(pos..pos + size)?; pos += size;
        if kind == 0x0F { return (size == 1 && alternative.is_none()).then_some(result); }
        if kind == 2 {
            if size < 5 || alternative.is_some() || result.len() >= 32 { return None; }
            result.push(Device { id: data[..4].try_into().ok()?, csn, ldn: result.len() as u8, supported: creative_audio(data),
                resources: Vec::new(), alternatives: 0 });
            ended_group = false;
            continue;
        }
        let Some(dev) = result.last_mut() else { continue };
        let resource = match kind {
            6 => {
                if size > 1 || ended_group { return None; }
                alternative = Some(dev.alternatives); dev.alternatives += 1;
                continue;
            }
            7 => {
                if size != 0 || alternative.is_none() { return None; }
                alternative = None; ended_group = true; continue;
            }
            4 if matches!(size, 2 | 3) => Resource::Irq(u16::from_le_bytes([data[0], data[1]]),
                if size == 3 { data[2] } else { 1 }),
            5 if size == 2 => Resource::Dma(data[0]),
            8 if size == 7 => Resource::Port {
                min: u16::from_le_bytes([data[1], data[2]]), max: u16::from_le_bytes([data[3], data[4]]),
                align: data[5], len: data[6],
            },
            9 if size == 3 => Resource::Port {
                min: u16::from_le_bytes([data[0], data[1]]), max: u16::from_le_bytes([data[0], data[1]]),
                align: 1, len: data[2],
            },
            // Memory-dependent devices and malformed known descriptors are
            // outside this SB audio subset, not permission to guess resources.
            4 | 5 | 8 | 9 | 0x81 | 0x85 | 0x86 => Resource::Unsupported,
            _ => continue,
        };
        dev.resources.push((alternative, resource));
    }
    None
}

fn requested_registers(dev: &Device, want: SbResources) -> Option<Vec<(u8, u8)>> {
    if !dev.supported || !matches!(want.base, 0x220 | 0x240 | 0x260 | 0x280)
        || !matches!(want.wiring.irq, 5 | 7 | 9 | 10)
        || !matches!(want.wiring.dma8, 0 | 1 | 3)
        || !want.wiring.dma16.is_none_or(|d| matches!(d, 5..=7)) { return None; }
    for alt in 0..dev.alternatives.max(1) {
        let mut registers = Vec::new();
        let (mut ports, mut irqs, mut dmas) = (0, 0, 0);
        let mut valid = true;
        for &(group, resource) in &dev.resources {
            if group.is_some_and(|n| n != alt) { continue; }
            match resource {
                Resource::Port { min, max, align, len } => {
                    let Some(&value) = [want.base, want.mpu, 0x388].get(ports) else { valid = false; break };
                    if value < min || value > max || len == 0
                        || !(value - min).is_multiple_of(u16::from(align.max(1))) { valid = false; break; }
                    registers.push((0x60 + ports as u8 * 2, (value >> 8) as u8));
                    registers.push((0x61 + ports as u8 * 2, value as u8));
                    ports += 1;
                }
                Resource::Irq(mask, flags) => {
                    if irqs != 0 || mask & (1 << want.wiring.irq) == 0 || flags & 1 == 0 { valid = false; break; }
                    registers.extend_from_slice(&[(0x70, want.wiring.irq), (0x71, 2)]); // high-edge ISA IRQ
                    irqs += 1;
                }
                Resource::Dma(mask) => {
                    let value = match dmas { 0 => want.wiring.dma8, 1 => want.wiring.dma16.unwrap_or(4), _ => { valid = false; break; } };
                    if value != 4 && mask & (1 << value) == 0 { valid = false; break; }
                    registers.push((0x74 + dmas, value)); dmas += 1;
                }
                Resource::Unsupported => { valid = false; break; }
            }
        }
        if valid && ports > 0 && irqs == 1 && dmas > 0 && (want.wiring.dma16.is_none() || dmas == 2) {
            return Some(registers);
        }
    }
    None
}

struct Snapshot { active: u8, registers: Vec<(u8, u8)> }

/// Absence permits legacy probing. Finding a PnP SB but failing to configure
/// it must not send that same card through legacy mixer restrapping.
#[derive(Debug, PartialEq, Eq)]
pub enum SbProbe { Absent, Configured(u16), Failed }

fn configure_devices<I: Io>(
    bus: &mut Bus<I>, devices: &[Device], want: Option<SbResources>,
    mut verify: impl FnMut(&mut I, u16) -> bool,
) -> SbProbe {
    if !devices.iter().any(|dev| dev.supported) {
        crate::compact_println!("ISA PnP: no Sound Blaster found; trying legacy DSP discovery");
        return SbProbe::Absent;
    }
    let Some(want) = want else {
        crate::compact_println!("ISA PnP: Sound Blaster found, but BLASTER resources are missing or invalid");
        return SbProbe::Failed;
    };
    for dev in devices {
        let Some(registers) = requested_registers(dev, want) else { continue };
        // An already-active target is ours to reconfigure; every other
        // active device (including sibling functions) keeps its resources.
        if devices.iter().any(|other| (other.csn, other.ldn) != (dev.csn, dev.ldn)
            && bus.conflicts(other, want)) { continue; }
        let Some(old) = bus.activate(dev, &registers) else { continue };
        bus.wait();
        if verify(&mut bus.io, want.base) {
            crate::compact_println!("ISA PnP: configured Creative audio CSN{} LDN{} at {:#x}, IRQ{} DMA{} HDMA{:?}",
                dev.csn, dev.ldn, want.base, want.wiring.irq, want.wiring.dma8, want.wiring.dma16);
            return SbProbe::Configured(want.base);
        }
        bus.key();
        bus.restore(dev, &old);
        crate::compact_println!("ISA PnP: audio DSP did not answer; restored previous configuration");
    }
    crate::compact_println!("ISA PnP: Sound Blaster configuration failed; legacy restrapping skipped");
    SbProbe::Failed
}

/// Discover PnP first, including cards already enabled by firmware/UNISOUND.
/// Configure a Creative audio device from BLASTER, then let the caller use
/// the ordinary DSP initialization at that exact base. LPC routing must work.
pub fn probe_sb<A: crate::Arch>(machine: &mut A, want: Option<SbResources>) -> SbProbe {
    let mut bus = Bus { io: Hardware(machine), rdp: READ_PORTS[0] };
    let cards = bus.isolate();
    let mut devices = Vec::new();
    let mut unreadable = false;
    for csn in cards {
        let Some(mut found) = bus.resource_stream(csn).and_then(|stream| parse_devices(csn, &stream)) else {
            crate::compact_println!("ISA PnP: malformed or unreadable resources on CSN{}; legacy probing skipped", csn);
            unreadable = true;
            continue;
        };
        for dev in &found {
            let [a, b, c, d] = dev.id;
            let vendor = [((a >> 2) & 31) + 64, (((a & 3) << 3) | (b >> 5)) + 64, (b & 31) + 64];
            crate::compact_println!("ISA PnP: CSN{} LDN{} {}{}{}{:02X}{:02X}{}",
                dev.csn, dev.ldn, vendor[0] as char, vendor[1] as char, vendor[2] as char, c, d,
                if dev.supported { " Sound Blaster" } else { "" });
        }
        devices.append(&mut found);
    }
    if unreadable { bus.wait(); return SbProbe::Failed; }
    let result = configure_devices(&mut bus, &devices, want,
        |io, base| super::sb16::dsp_reset_at(io.0, base));
    bus.wait();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, collections::VecDeque};

    fn request() -> SbResources {
        SbResources { base: 0x220, mpu: 0x330,
            wiring: SbWiring { irq: 7, dma8: 1, dma16: Some(5) } }
    }
    fn fixture() -> Vec<u8> {
        vec![
            0x15, 0x0E, 0x8C, 0, 0x31, 0, // CTL0031 audio LDN 0
            0x47, 1, 0x20, 2, 0x80, 2, 0x20, 16, // base 220..280
            0x47, 1, 0, 3, 0x30, 3, 0x30, 2, // MPU 300/330
            0x4B, 0x88, 3, 4, // fixed OPL 388
            0x23, 0xA0, 0, 1, // IRQ 5/7, high edge
            0x2A, 0x0A, 0, // DMA 1/3
            0x2A, 0xE0, 1, // DMA 5/6/7
            0x79, 0,
        ]
    }
    #[test]
    fn validates_resources_and_ignores_non_audio_ids() {
        let mut devices = parse_devices(3, &fixture()).unwrap();
        let regs = requested_registers(&devices[0], request()).unwrap();
        assert!(regs.contains(&(0x60, 2)) && regs.contains(&(0x61, 0x20)));
        assert!(regs.contains(&(0x70, 7)) && regs.contains(&(0x71, 2)));
        assert!(regs.contains(&(0x74, 1)) && regs.contains(&(0x75, 5)));
        let mut bad = request(); bad.base = 0x230;
        assert!(requested_registers(&devices[0], bad).is_none());
        bad = request(); bad.wiring.irq = 10;
        assert!(requested_registers(&devices[0], bad).is_none());
        devices[0].supported = creative_audio(&[0x0E, 0x8C, 0, 0x21]); // wavetable
        assert!(requested_registers(&devices[0], request()).is_none());
    }
    #[test]
    fn never_mixes_dependent_alternatives() {
        let mut bytes = fixture(); bytes.truncate(6 + 8 + 8 + 4);
        bytes.extend_from_slice(&[
            0x30, 0x22, 0x20, 0, 0x2A, 2, 0, 0x2A, 0x20, 1, // IRQ5/DMA1/5
            0x30, 0x22, 0x80, 0, 0x2A, 8, 0, 0x2A, 0x20, 1, // IRQ7/DMA3/5
            0x38, 0x79, 0,
        ]);
        let devices = parse_devices(1, &bytes).unwrap();
        assert!(requested_registers(&devices[0], request()).is_none()); // IRQ7/DMA1
        let mut good = request(); good.wiring.dma8 = 3;
        assert!(requested_registers(&devices[0], good).is_some());
        for n in 0..bytes.len() { assert!(parse_devices(1, &bytes[..n]).is_none()); }
    }

    struct Fake { index: u8, regs: [u8; 256], refuse: Option<u8>, writes: Vec<(u16, u8)>,
        serial: VecDeque<u8>, data: VecDeque<u8> }
    impl Fake {
        fn new() -> Self { Self { index: 0, regs: [0; 256], refuse: None, writes: Vec::new(), serial: VecDeque::new(), data: VecDeque::new() } }
    }
    impl Io for Fake {
        fn out(&mut self, port: u16, value: u8) {
            self.writes.push((port, value));
            if port == ADDRESS { self.index = value; }
            if port == WRITE && Some(self.index) != self.refuse { self.regs[self.index as usize] = value; }
        }
        fn input(&mut self, _port: u16) -> u8 {
            match self.index {
                1 => self.serial.pop_front().unwrap_or(0xFF),
                5 => u8::from(!self.data.is_empty()),
                4 => self.data.pop_front().unwrap_or(0xFF),
                _ => self.regs[self.index as usize],
            }
        }
        fn delay(&mut self, _us: u64) {}
    }
    #[test]
    fn activation_verifies_and_rolls_back_failed_programming() {
        let dev = parse_devices(3, &fixture()).unwrap().remove(0);
        let regs = requested_registers(&dev, request()).unwrap();
        let mut bus = Bus { io: Fake::new(), rdp: 0x213 };
        assert!(bus.activate(&dev, &regs).is_some());
        assert_eq!((bus.io.regs[3], bus.io.regs[7], bus.io.regs[0x30]), (3, 0, 1));
        assert!(bus.activate(&dev, &regs).is_some()); // already matches; keep active
        let mut bus = Bus { io: Fake::new(), rdp: 0x213 };
        bus.io.regs[0x61] = 0x40;
        bus.io.refuse = Some(0x75);
        assert!(bus.activate(&dev, &regs).is_none());
        assert_eq!(bus.io.regs[0x30], 0);
        assert_eq!(bus.io.regs[0x61], 0x40);
        assert_eq!(bus.io.regs[0x70], 0);
        assert!(!bus.io.writes.windows(2).any(|w| w == [(ADDRESS, 0x30), (WRITE, 1)]));
    }
    #[test]
    fn initiation_key_and_serial_checksum() {
        let mut bus = Bus { io: Fake::new(), rdp: 0x213 };
        bus.key();
        let bytes: Vec<_> = bus.io.writes.iter().map(|(_, v)| *v).collect();
        assert_eq!(&bytes[..10], &[0, 0, 0x6A, 0xB5, 0xDA, 0xED, 0xF6, 0xFB, 0x7D, 0xBE]);
        assert_eq!(bytes.len(), 34);
        assert!(!valid_serial(&[0; 9]));
        let mut serial = [0x0E, 0x8C, 0, 0x24, 1, 2, 3, 4, 0];
        let mut checksum = 0x6A;
        for byte in &serial[..8] { for bit in 0..8 { checksum = lfsr(checksum, (byte >> bit) & 1); } }
        serial[8] = checksum;
        assert!(valid_serial(&serial));
        serial[2] ^= 1;
        assert!(!valid_serial(&serial));
    }
    #[test]
    fn serial_isolation_resource_stream_and_active_conflicts() {
        let mut bus = Bus { io: Fake::new(), rdp: 0x213 };
        let mut serial = [0x0E, 0x8C, 0, 0x24, 1, 2, 3, 4, 0];
        let mut checksum = 0x6A;
        for bit in 0..64 { checksum = lfsr(checksum, (serial[bit / 8] >> (bit % 8)) & 1); }
        serial[8] = checksum;
        for byte in serial {
            for bit in 0..8 {
                bus.io.serial.extend(if byte & (1 << bit) != 0 { [0x55, 0xAA] } else { [0xFF, 0xFF] });
            }
        }
        assert_eq!(bus.isolate(), vec![1]);
        assert_eq!(bus.io.regs[6], 1);
        bus.io.data.extend(serial);
        bus.io.data.extend(fixture());
        let stream = bus.resource_stream(1).unwrap();
        let dev = parse_devices(1, &stream).unwrap().remove(0);
        assert!(!bus.conflicts(&dev, request()));
        bus.io.regs[0x30] = 1;
        bus.io.regs[0x70] = 7;
        assert!(bus.conflicts(&dev, request()));
        bus.io.regs[0x70] = 10;
        bus.io.regs[0x60] = 6; bus.io.regs[0x61] = 0x20; // alias of 220
        assert!(bus.conflicts(&dev, request()));
        assert!(!port_overlap(0x240, 16, 0x220, 16));
    }

    #[test]
    fn pnp_first_reconfigures_active_card_and_restores_on_dsp_failure() {
        let devices = parse_devices(3, &fixture()).unwrap();
        let mut bus = Bus { io: Fake::new(), rdp: 0x213 };
        bus.io.regs[0x30] = 1;
        bus.io.regs[0x60] = 2; bus.io.regs[0x61] = 0x40;
        bus.io.regs[0x70] = 5;
        assert_eq!(configure_devices(&mut bus, &devices, Some(request()), |_, base| base == 0x220),
            SbProbe::Configured(0x220));
        assert_eq!(bus.io.regs[0x61], 0x20);
        assert_eq!(bus.io.regs[0x70], 7);
        assert_eq!(bus.io.regs[0x30], 1);

        let mut new = request(); new.base = 0x240;
        assert_eq!(configure_devices(&mut bus, &devices, Some(new), |_, _| false), SbProbe::Failed);
        assert_eq!(bus.io.regs[0x61], 0x20);
        assert_eq!(bus.io.regs[0x70], 7);
        assert_eq!(bus.io.regs[0x30], 1);
    }

    #[test]
    fn only_pnp_absence_allows_legacy_fallback() {
        let devices = parse_devices(3, &fixture()).unwrap();
        let mut bus = Bus { io: Fake::new(), rdp: 0x213 };
        assert_eq!(configure_devices(&mut bus, &[], None, |_, _| panic!()), SbProbe::Absent);
        assert_eq!(configure_devices(&mut bus, &devices, None, |_, _| panic!()), SbProbe::Failed);
        let mut bad = request(); bad.wiring.irq = 10;
        assert_eq!(configure_devices(&mut bus, &devices, Some(bad), |_, _| panic!()), SbProbe::Failed);
        assert!(bus.io.writes.is_empty());
    }

}
