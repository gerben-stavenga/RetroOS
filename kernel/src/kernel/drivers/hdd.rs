//! ATA/IDE transport: bus-master DMA, with PIO fallback.
//!
//! Polled LBA28 or legacy CHS commands. PIIX3/PIIX4 controllers and
//! MWDMA2-capable drives use DMA; older controllers retain PIO access.
//!
//! One [`AtaDisk`] value per drive: it owns its controller ports and drive
//! select, so a machine with a primary master AND a secondary slave is just
//! two values. The driver's whole job is "is there a drive here, and how do I
//! move sectors to and from it" — which disk is the boot disk, and what lives
//! on it, is decided by `startup`.

use super::storage::{Buffer, Command, Error, Hardware, Operation, Storage, poll, poll_with_clock};
#[cfg(test)]
use super::storage::COMMAND_TIMEOUT_NS;
use crate::kernel::portio::{inb, insw, outb, outl, outsw, now_ns};
use super::dma::Region;
use crate::kernel::pci;

/// ATA register offsets from base port
mod reg {
    pub const DATA: u16 = 0;           // Read/Write data (16-bit)
    pub const FEATURES: u16 = 1;       // Features register (write)
    pub const SECTOR_COUNT: u16 = 2;   // Number of sectors
    pub const LBA_0_7: u16 = 3;        // LBA bits 0-7
    pub const LBA_8_15: u16 = 4;       // LBA bits 8-15
    pub const LBA_16_23: u16 = 5;      // LBA bits 16-23
    pub const LBA_24_27_FLAGS: u16 = 6; // LBA bits 24-27 + flags
    pub const STATUS: u16 = 7;         // Status register (read)
    pub const COMMAND: u16 = 7;        // Command register (write)
}

/// ATA status register bits
mod status {
    pub const BSY: u8 = 0x80;  // Busy
    pub const DRDY: u8 = 0x40; // Drive ready
    pub const DRQ: u8 = 0x08;  // Data request (ready to transfer)
    pub const ERR: u8 = 0x01;  // Error
}

/// ATA commands
mod cmd {
    pub const READ_SECTORS: u8 = 0x20;
    pub const WRITE_SECTORS: u8 = 0x30;
    pub const CACHE_FLUSH: u8 = 0xE7;
    pub const IDENTIFY: u8 = 0xEC;
    pub const INITIALIZE_PARAMETERS: u8 = 0x91;
}

/// The two legacy ISA channels: (base, control). Every PC has these at fixed
/// ports; anything beyond them is PCI-configured and out of scope here.
pub const CHANNELS: [(u16, u16); 2] = [(0x1F0, 0x3F6), (0x170, 0x376)];

/// The LBA28 addressing ceiling — this driver cannot reach past it.
const LBA28_MAX: u64 = 1 << 28;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Addressing {
    Lba28(u64),
    Chs { cylinders: u16, heads: u8, sectors: u8 },
}

impl Addressing {
    fn identify(words: &[u16; 256]) -> Option<Self> {
        if words[49] & (1 << 9) != 0 {
            let sectors = u64::from(words[60]) | (u64::from(words[61]) << 16);
            return (sectors > 0).then_some(Self::Lba28(sectors.min(LBA28_MAX)));
        }
        // Use the device's default translation, not a BIOS-selected one.
        // INITIALIZE DEVICE PARAMETERS below installs these heads/sectors
        // after reset, including on ATA-1 disks without valid words 54-58.
        let (cylinders, heads, sectors) = (words[1], words[3], words[6]);
        if cylinders == 0 || !(1..=16).contains(&heads) || !(1..=255).contains(&sectors) {
            return None;
        }
        Some(Self::Chs { cylinders, heads: heads as u8, sectors: sectors as u8 })
    }

    fn capacity(self) -> u64 {
        match self {
            Self::Lba28(sectors) => sectors,
            Self::Chs { cylinders, heads, sectors } =>
                u64::from(cylinders) * u64::from(heads) * u64::from(sectors),
        }
    }

    /// Drive/head, sector number, cylinder low, cylinder high (LBA uses the
    /// same registers). CHS sectors are one-based; heads/cylinders are not.
    fn taskfile(self, drive: u8, lba: u32) -> [u8; 4] {
        assert!(u64::from(lba) < self.capacity());
        let device = 0xa0 | (drive << 4);
        match self {
            Self::Lba28(_) => [device | 0x40 | ((lba >> 24) as u8 & 0xf),
                              lba as u8, (lba >> 8) as u8, (lba >> 16) as u8],
            Self::Chs { heads, sectors, .. } => {
                let track = lba / u32::from(sectors);
                let cylinder = track / u32::from(heads);
                [device | (track % u32::from(heads)) as u8,
                 (lba % u32::from(sectors) + 1) as u8,
                 cylinder as u8, (cylinder >> 8) as u8]
            }
        }
    }
}

fn wait_status(mut read: impl FnMut() -> u8, now: impl FnMut() -> u64,
               required: u8) -> Result<(), Error> {
    poll_with_clock(now, || {
        let s = read();
        if s == 0 || s == 0xff { return Some(Err(Error::Device(s as u16))); }
        if s & status::BSY == 0 {
            if s & (status::ERR | 0x20) != 0 { return Some(Err(Error::Device(s as u16))); }
            if s & required == required { return Some(Ok(())); }
        }
        None
    }).unwrap_or(Err(Error::Timeout))
}

fn needs_cache_flush(words: &[u16; 256]) -> bool {
    // Older ATA disks (including 86Box's IDE disk) advertise neither a write
    // cache nor FLUSH CACHE and abort E7h. Their completed writes need no
    // extra command. If a write cache exists, keep requiring a flush even
    // when the flush capability is missing: silently succeeding would lose
    // the filesystem's durability guarantee.
    let write_cache = words[82] & (1 << 5) != 0;
    let flush = words[83] & 0xc000 == 0x4000 && words[83] & (1 << 12) != 0;
    write_cache || flush
}

/// One ATA drive: a channel plus a master/slave select.
pub struct Ata {
    base: u16,
    /// 0 = master, 1 = slave. Shifted into bit 4 of the drive/head register.
    drive: u8,
    addressing: Addressing,
    /// Always 4 bytes ("ata0".."ata3"); copied into the common disk wrapper.
    name: [u8; 4],
    mwdma2: bool,
    cache_flush: bool,
    bus_master: Option<BusMaster>,
}

impl Ata {
    /// Probe one drive. `None` when nothing answers — bounded, so a machine
    /// with no ATA at all (UEFI/NVMe-only, floating bus reading 0xFF) returns
    /// quickly instead of busy-waiting on an absent controller.
    ///
    /// IDENTIFY is the real presence test, not the status register: an ABSENT
    /// SLAVE answers DRDY because the master drives the bus on its behalf, so
    /// a status check alone invents a phantom disk. A drive that won't
    /// IDENTIFY (no device, or ATAPI, which we don't support) is not a disk.
    fn probe(base: u16, drive: u8) -> Option<Self> {
        let select = 0xA0 | (drive << 4);

        outb(base + reg::LBA_24_27_FLAGS, select);

        let mut ready = false;
        for _ in 0..100_000 {
            let s = inb(base + reg::STATUS);
            if s == 0xFF {
                return None; // floating bus — no controller decodes these ports
            }
            if (s & (status::BSY | status::DRDY)) == status::DRDY {
                ready = true;
                break;
            }
        }
        if !ready {
            return None;
        }

        // Channel 0 master is "ata0", channel 0 slave "ata1", and so on.
        let index = if base == CHANNELS[1].0 { 2 } else { 0 } + drive;
        let name = [b'a', b't', b'a', b'0' + index];

        let mut disk = Ata { base, drive, addressing: Addressing::Lba28(0), name, mwdma2: false,
                             cache_flush: true, bus_master: None };
        disk.addressing = disk.identify_addressing()?;
        if let Addressing::Chs { heads, sectors, .. } = disk.addressing {
            disk.select();
            disk.wait(status::DRDY).ok()?;
            outb(base + reg::LBA_24_27_FLAGS, 0xa0 | (drive << 4) | (heads - 1));
            outb(base + reg::SECTOR_COUNT, sectors);
            outb(base + reg::COMMAND, cmd::INITIALIZE_PARAMETERS);
            for _ in 0..4 { inb(base + reg::STATUS); }
            disk.wait(status::DRDY).ok()?;
        }
        Some(disk)
    }

    /// Addressing and capacity from IDENTIFY. `None` if the drive errors or
    /// never raises DRQ (bounded wait — a non-existent slave typically hangs
    /// BSY forever, which is exactly what we must not do here).
    fn identify_addressing(&mut self) -> Option<Addressing> {
        self.select();
        outb(self.base + reg::SECTOR_COUNT, 0);
        outb(self.base + reg::LBA_0_7, 0);
        outb(self.base + reg::LBA_8_15, 0);
        outb(self.base + reg::LBA_16_23, 0);
        outb(self.base + reg::COMMAND, cmd::IDENTIFY);

        for _ in 0..1_000_000 {
            let s = inb(self.base + reg::STATUS);
            if s & status::BSY != 0 { continue; }
            if s == 0 || (s & status::ERR) != 0 {
                return None; // no device, or IDENTIFY unsupported (ATAPI)
            }
            if s & status::DRQ != 0 {
                let mut words = [0u16; 256];
                insw(self.base + reg::DATA, &mut words);
                self.mwdma2 = words[49] & (1 << 8) != 0 && words[63] & 4 != 0;
                self.cache_flush = needs_cache_flush(&words);
                return Addressing::identify(&words);
            }
        }
        None
    }

    /// Point the channel at this drive. Every transfer re-selects, because the
    /// other drive on the same channel may have been used in between — and a
    /// stale select is not benign: waiting on the status register while an
    /// ABSENT drive is selected spins forever on a floating bus.
    ///
    /// The spec wants ~400 ns before the status register is meaningful after a
    /// select; four status reads cover it (each is an ISA cycle).
    fn select(&self) {
        outb(self.base + reg::LBA_24_27_FLAGS, 0xA0 | (self.drive << 4));
        for _ in 0..4 {
            inb(self.base + reg::STATUS);
        }
    }

    /// Bounded status polling; an absent or faulted drive must not wedge the
    /// kernel while a filesystem waits for I/O.
    fn wait(&self, required: u8) -> Result<(), Error> {
        wait_status(|| inb(self.base + reg::STATUS), now_ns, required)
    }

    /// Program the taskfile for a `batch`-sector transfer at `lba`.
    ///
    /// Select BEFORE waiting: the channel may still be pointed at the other
    /// drive from a previous probe or transfer, and `wait_ready` against an
    /// absent drive never returns.
    fn issue(&self, lba: u32, batch: u32, command: u8) -> Result<(), Error> {
        self.select();
        self.wait(status::DRDY)?;
        let [device, sector, low, high] = self.addressing.taskfile(self.drive, lba);
        outb(self.base + reg::LBA_24_27_FLAGS, device);
        outb(self.base + reg::FEATURES, 0);
        // A sector count of 0 means 256 — the maximum one command can carry.
        outb(self.base + reg::SECTOR_COUNT, if batch == 256 { 0 } else { batch as u8 });
        outb(self.base + reg::LBA_0_7, sector);
        outb(self.base + reg::LBA_8_15, low);
        outb(self.base + reg::LBA_16_23, high);
        outb(self.base + reg::COMMAND, command);
        Ok(())
    }
}

/// ATA uses the same staging and request engine as DMA controllers. The PIO
/// transport supplies the port data phase for machines without bus mastering.
pub type AtaDisk = Storage<Ata>;

impl Storage<Ata> {
    fn probe<A: crate::Arch>(machine: &mut A, base: u16, drive: u8) -> Option<Self> {
        let mut ata = Ata::probe(base, drive)?;
        let sectors = ata.addressing.capacity();
        let name = ata.name;
        let buffer = if ata.mwdma2 {
            if let Some((controller, buffer)) = BusMaster::probe(machine, &ata) {
                ata.bus_master = Some(controller);
                buffer
            } else { Buffer::pio(256) }
        } else { Buffer::pio(256) };
        lib::compact_println!("ATA: {} {} {}", core::str::from_utf8(&name).unwrap_or("ata?"),
            if matches!(ata.addressing, Addressing::Chs { .. }) { "CHS" } else { "LBA28" },
            if ata.bus_master.is_some() { "DMA" } else { "PIO" });
        Some(Self::new(ata, buffer, sectors,
            core::str::from_utf8(&name).unwrap_or("ata?")))
    }
}

/// Reset each channel once, before configuring either drive. Resetting for
/// the slave probe would undo the master's newly selected DMA mode.
pub fn probe<A: crate::Arch>(machine: &mut A) -> alloc::vec::Vec<AtaDisk> {
    let mut disks = alloc::vec::Vec::new();
    for (base, ctrl) in CHANNELS {
        outb(ctrl, 0x04);
        // SRST must be asserted for at least 5 us. Port reads also provide
        // ordering on legacy machines whose clocks cannot yet be calibrated.
        for _ in 0..256 { inb(ctrl); }
        outb(ctrl, 0);
        for _ in 0..256 { inb(ctrl); }
        for drive in 0..2 {
            if let Some(disk) = AtaDisk::probe(machine, base, drive) { disks.push(disk); }
        }
    }
    disks
}

// Both devices on one legacy channel share a taskfile and data port.
static CHANNEL_LOCKS: [spin::Mutex<()>; 2] = [spin::Mutex::new(()), spin::Mutex::new(())];

impl Hardware for Ata {
    fn execute(&mut self, c: Command, buffer: &mut Buffer) -> Result<(), Error> {
        let channel = usize::from(self.base == CHANNELS[1].0);
        let _channel = CHANNEL_LOCKS[channel].lock();
        if c.operation == Operation::Flush {
            self.select();
            self.wait(status::DRDY)?;
            if !self.cache_flush { return Ok(()); }
            outb(self.base + reg::COMMAND, cmd::CACHE_FLUSH);
            return self.wait(status::DRDY);
        }
        if let Some(bus_master) = &self.bus_master {
            let command = if c.operation == Operation::Read { 0xc8 } else { 0xca };
            let direction = bus_master.prepare(c, buffer);
            self.issue(c.lba as u32, c.sectors, command)?;
            return bus_master.complete(self.base, direction);
        }
        let command = match c.operation {
            Operation::Read => cmd::READ_SECTORS,
            Operation::Write => cmd::WRITE_SECTORS,
            Operation::Flush => unreachable!(),
        };
        self.issue(c.lba as u32, c.sectors, command)?;
        for words in buffer.words()[..c.sectors as usize * 256].chunks_exact_mut(256) {
            self.wait(status::DRQ)?;
            match c.operation {
                Operation::Read => insw(self.base + reg::DATA, words),
                Operation::Write => outsw(self.base + reg::DATA, words),
                Operation::Flush => unreachable!(),
            }
        }
        self.wait(status::DRDY)
    }
}

/// PCI IDE bus-master access. PRDs split at 64 KiB physical boundaries; both
/// descriptors and transfer memory must be below 4 GiB on legacy IDE.
struct BusMaster { base: u16, dma: Region }

impl BusMaster {
    fn probe<A: crate::Arch>(machine: &mut A, ata: &Ata) -> Option<(Self, Buffer)> {
        let (bus, dev, func) = pci::find_class(machine, 1, 1)?;
        // IDE bus-master registers are standard; transfer timings are not.
        // PIIX3/PIIX4 provide independent master/slave MWDMA2 timings.
        let id = pci::read32(machine, bus, dev, func, 0);
        if !matches!(id, 0x7010_8086 | 0x7111_8086) { return None; }
        let interface = (pci::read32(machine, bus, dev, func, 8) >> 8) as u8;
        let secondary = ata.base == CHANNELS[1].0;
        let native = if secondary { 4 } else { 1 };
        if interface & 0x80 == 0 || interface & native != 0 { return None; }
        let bar = pci::read32(machine, bus, dev, func, 0x20);
        if bar & 1 == 0 || bar & 0xfffffff0 == 0 || bar > 0xffff { return None; }
        let base = (bar as u16 & !0xf) + if secondary { 8 } else { 0 };
        let dma = Region::allocate(machine, 33, 32)?;
        let command = pci::read32(machine, bus, dev, func, 4);
        pci::write32(machine, bus, dev, func, 4, (command & 0xffff) | 5);
        // Program MWDMA2 timings (ISP=2, RTC=3), retaining PIO0 for
        // IDENTIFY and other data-port commands via DMA-only timing (DTE).
        // IDETIM: primary word 40h, secondary word 42h; slave nibble in 44h.
        // Register layout: https://github.com/torvalds/linux/blob/master/drivers/ata/ata_piix.c
        let timings = pci::read32(machine, bus, dev, func, 0x40);
        let slaves = pci::read32(machine, bus, dev, func, 0x44);
        let (timings, slaves) = piix_mwdma2(timings, slaves, secondary, ata.drive);
        pci::write32(machine, bus, dev, func, 0x44, slaves);
        pci::write32(machine, bus, dev, func, 0x40, timings);
        if id == 0x7111_8086 {
            let udma = pci::read32(machine, bus, dev, func, 0x48);
            let device = u32::from(secondary) * 2 + u32::from(ata.drive);
            pci::write32(machine, bus, dev, func, 0x48, udma & !(1 << device));
        }
        outb(base, 0); // stop bus mastering before SET FEATURES
        outb(base + 2, inb(base + 2) | 6);
        ata.select();
        ata.wait(status::DRDY).ok()?;
        outb(ata.base + reg::FEATURES, 3); // Set transfer mode
        outb(ata.base + reg::SECTOR_COUNT, 0x22); // Multiword DMA mode 2
        outb(ata.base + reg::COMMAND, 0xef); // SET FEATURES
        for _ in 0..4 { inb(ata.base + reg::STATUS); }
        ata.wait(status::DRDY).ok()?;
        // Advertise DMA capability for the selected drive in BMIDE status.
        outb(base + 2, inb(base + 2) | (1 << (5 + ata.drive)) | 6);
        let buffer = unsafe { dma.buffer(4096, 256 * 512) };
        Some((Self { base, dma }, buffer))
    }

    fn prepare(&self, c: Command, buffer: &mut Buffer) -> u8 {
        let direction = if c.operation == Operation::Read { 8 } else { 0 };
        outb(self.base, direction); // stop before replacing PRDT
        let table = ide_prds(buffer.physical_address().unwrap() as u32, c.sectors * 512);
        for (index, word) in table.iter().enumerate() {
            unsafe { core::ptr::write_volatile((self.dma.va as *mut u32).add(index), *word); }
        }
        outl(self.base + 4, self.dma.phys as u32);
        outb(self.base + 2, inb(self.base + 2) | 6);
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        direction
    }

    fn complete(&self, ata_base: u16, direction: u8) -> Result<(), Error> {
        outb(self.base, direction | 1);
        let result = poll(|| {
            let status = inb(self.base + 2);
            if status & 2 != 0 { return Some(Err(Error::Device(status as u16))); }
            if status & 5 == 4 { return Some(Ok(())); } // IRQ set, DMA inactive
            None
        }).unwrap_or(Err(Error::Timeout));
        outb(self.base, direction);
        let status = inb(ata_base + reg::STATUS);
        outb(self.base + 2, inb(self.base + 2) | 6);
        if status & 0x21 != 0 { return Err(Error::Device(status as u16)); }
        result
    }
}

fn piix_mwdma2(mut timings: u32, mut slaves: u32, secondary: bool, drive: u8) -> (u32, u32) {
    let channel = u32::from(secondary) * 16;
    let device = channel + u32::from(drive) * 4;
    timings = (timings & !(0xf << device)) | (0x9 << device); // TIME + DTE
    timings |= 0x4000 << channel; // independent slave timings
    if drive == 0 {
        timings = (timings & !(0x3300 << channel)) | (0x2300 << channel);
    } else {
        let shift = u32::from(secondary) * 4;
        slaves = (slaves & !(0xf << shift)) | (0xb << shift);
    }
    (timings, slaves)
}

fn ide_prds(mut phys: u32, mut bytes: u32) -> [u32; 6] {
    assert!(bytes > 0 && bytes <= 128 * 1024);
    let mut table = [0; 6];
    for entry in table.chunks_exact_mut(2) {
        let size = bytes.min(0x10000 - (phys & 0xffff));
        entry[0] = phys;
        bytes -= size;
        entry[1] = (size & 0xffff) | if bytes == 0 { 1 << 31 } else { 0 };
        if bytes == 0 { return table; }
        phys = phys.checked_add(size).expect("IDE DMA crosses 4 GiB");
    }
    unreachable!("128 KiB needs at most three IDE PRDs")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn legacy_identify() -> [u16; 256] {
        let mut words = [0; 256];
        words[1] = 615;
        words[3] = 4;
        words[6] = 17;
        words
    }

    #[test]
    fn identify_uses_chs_without_lba_and_rejects_invalid_geometry() {
        let mut words = legacy_identify();
        // Unadvertised LBA words and an old BIOS translation must not win.
        words[60] = 0xffff;
        words[61] = 0xffff;
        words[53] = 1;
        words[54] = 1024;
        words[55] = 16;
        words[56] = 63;
        let chs = Addressing::identify(&words).unwrap();
        assert_eq!(chs, Addressing::Chs { cylinders: 615, heads: 4, sectors: 17 });
        assert_eq!(chs.capacity(), 41820);
        for (word, value) in [(1, 0), (3, 0), (3, 17), (6, 0), (6, 256)] {
            let mut invalid = words;
            invalid[word] = value;
            assert_eq!(Addressing::identify(&invalid), None);
        }
        words[49] = 1 << 9;
        assert_eq!(Addressing::identify(&words), Some(Addressing::Lba28(LBA28_MAX)));
        words[60] = 0;
        words[61] = 0;
        assert_eq!(Addressing::identify(&words), None);
    }

    #[test]
    fn chs_taskfiles_roll_over_sector_head_and_cylinder() {
        let chs = Addressing::identify(&legacy_identify()).unwrap();
        assert_eq!(chs.taskfile(0, 0), [0xa0, 1, 0, 0]);
        assert_eq!(chs.taskfile(0, 16), [0xa0, 17, 0, 0]);
        assert_eq!(chs.taskfile(0, 17), [0xa1, 1, 0, 0]);
        assert_eq!(chs.taskfile(0, 68), [0xa0, 1, 1, 0]);
        assert_eq!(chs.taskfile(1, 256 * 68), [0xb0, 1, 0, 1]);
        assert_eq!(chs.taskfile(1, 41819), [0xb3, 17, 0x66, 2]);
        let largest = Addressing::Chs { cylinders: 65535, heads: 16, sectors: 255 };
        assert_eq!(largest.taskfile(1, largest.capacity() as u32 - 1),
                   [0xbf, 255, 0xfe, 0xff]);
        assert_eq!(Addressing::Lba28(LBA28_MAX).taskfile(1, 0x0abcdef0),
                   [0xfa, 0xf0, 0xde, 0xbc]);
    }

    #[test]
    fn legacy_disks_without_write_cache_need_no_flush_command() {
        let mut words = [0; 256];
        assert!(!needs_cache_flush(&words));
        words[83] = 0x4000; // 86Box: valid capabilities, no FLUSH CACHE
        assert!(!needs_cache_flush(&words));
        words[82] = 1 << 5;
        assert!(needs_cache_flush(&words)); // never hide a caching disk's error
        words[82] = 0;
        words[83] = 0x5000;
        assert!(needs_cache_flush(&words));
        assert!(needs_cache_flush(&[0xffff; 256]));
    }

    #[test]
    fn slow_flush_uses_elapsed_time_not_poll_count() {
        let mut polls = 0;
        let mut ns = 0;
        let result = wait_status(|| {
            polls += 1;
            if polls <= 1_000_001 { status::BSY } else { status::DRDY }
        }, || { ns += 1_000; ns }, status::DRDY);
        assert_eq!(result, Ok(()));
        assert!(ns < COMMAND_TIMEOUT_NS);
    }

    #[test]
    fn ata_wait_times_out_and_reports_device_errors() {
        let mut ns = 0;
        assert_eq!(wait_status(|| status::BSY, || {
            ns += COMMAND_TIMEOUT_NS / 2;
            ns
        }, status::DRDY), Err(Error::Timeout));
        for status in [0, 0xff, status::DRDY | status::ERR, status::DRDY | 0x20] {
            assert_eq!(wait_status(|| status, || 0, self::status::DRDY),
                       Err(Error::Device(status as u16)));
        }
    }

    #[test]
    fn piix_timings_preserve_other_drive_and_channel() {
        let (primary, slaves) = piix_mwdma2(0xa55a8000, 0xabcdef12, false, 0);
        assert_eq!(primary, 0xa55ae309);
        assert_eq!(slaves, 0xabcdef12);
        let (both, slaves) = piix_mwdma2(primary, slaves, false, 1);
        assert_eq!(both, 0xa55ae399);
        assert_eq!(slaves, 0xabcdef1b);
        let (secondary, slaves) = piix_mwdma2(both, slaves, true, 1);
        assert_eq!(secondary & 0xffff, both & 0xffff);
        assert_eq!(slaves, 0xabcdefbb);
    }
    #[test]
    fn ide_descriptors_split_at_64k_and_mark_only_final_entry() {
        assert_eq!(ide_prds(0x12345000, 128 * 1024),
            [0x12345000, 0xb000, 0x12350000, 0, 0x12360000, 0x80005000]);
        assert_eq!(ide_prds(0x10000, 65536), [0x10000, 0x80000000, 0, 0, 0, 0]);
        assert_eq!(ide_prds(0xfffffe00, 512), [0xfffffe00, 0x80000200, 0, 0, 0, 0]);
    }
}
