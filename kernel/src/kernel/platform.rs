//! The machine, probed once, as types.
//!
//! Everything the kernel needs to know about the hardware/host it landed on
//! is detected EAGERLY here, at one fixed point early in startup, and frozen
//! into [`Platform`] — an immutable, write-once description. Policy code
//! (VGA passthrough vs emulation, native vs substitute BIOS, console
//! routing, per-personality I/O bitmaps) derives from these types with
//! exhaustive matches; nothing downstream probes hardware lazily or keeps a
//! private `static` verdict. Adding an enum variant breaks every policy
//! site at compile time — deliberately.

use crate::println;
use arch_abi::Arch;

pub struct Platform {
    pub host: Host,
    pub display: Display,
    pub firmware: Firmware,
    pub audio: Audio,
    pub media: Media,
    pub debug: DebugSink,
}

/// What is running the kernel.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Host {
    /// QEMU (the loader saw fw_cfg): synthetic-retrace fabrication etc.
    Qemu,
    /// Real hardware — or an emulator without fw_cfg (Bochs), which earns
    /// real-hardware treatment: trust the devices.
    #[cfg(not(feature = "hosted"))]
    Metal,
    /// The hosted interpreter backend (arch-interp as a host process).
    #[cfg(feature = "hosted")]
    Interp,
}

/// The display path. Exactly one of these is true, decided here — not
/// re-derived piecemeal by render/console/IOPB code.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Display {
    /// A real VGA card answered the SEQ-register probe: guests program the
    /// hardware directly (passthrough port window); console = VGA text.
    #[cfg(not(feature = "hosted"))]
    VgaCard,
    /// No card, but the loader handed over a linear framebuffer (UEFI/GOP):
    /// the kernel-emulated VGA renders through fbcon.
    #[cfg(not(feature = "hosted"))]
    Framebuffer,
    /// No card or framebuffer, but a host window installed a present sink
    /// (retroos-play): the emulated VGA renders into the window.
    #[cfg(feature = "hosted")]
    HostWindow,
    /// Nothing to display on (headless interp run): the emulated VGA still
    /// models state — screendumps and --screenshot remain possible.
    Headless,
}

/// Real-mode firmware at the legacy ROM window.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Firmware {
    /// A legacy BIOS owns F000 (far-JMP at the reset vector): DOS threads
    /// use the real ROM services.
    #[cfg(not(feature = "hosted"))]
    NativeBios,
    /// No ROM (UEFI metal, interp's zeroed RAM): the DOS personality
    /// installs its substitute Rust BIOS (`dos/bios.rs`).
    Substitute,
}

/// The audio path — exactly one of these is true, decided here. Replaces
/// three lazy probes: vsb's `ensure_mode` (SB card), ac97's PRESENT atomic,
/// and sound's port-window signature cache.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Audio {
    /// A real Sound Blaster answered the DSP-status probe (legacy metal,
    /// QEMU `sb16`): guest DSP/mixer traffic forwards to the card and only
    /// the 8237 stays virtual. Implies a real OPL — the 0x388 window is
    /// part of the DOS io_policy template, not a runtime grant.
    SbPassthrough,
    /// No card; the software SB16 renders through the kernel sound API into an
    /// Intel HD Audio controller found on PCI (QEMU `intel-hda`, modern metal).
    EmulatedHda,
    /// No card; the software SB16 renders through the kernel sound API into
    /// the AC'97 codec found on PCI (UEFI-class metal).
    EmulatedAc97,
    /// No card or codec; rendering goes to the canonical audio port window
    /// (the interpreter's WAV sink answered the signature probe).
    EmulatedPortWindow,
    /// Nothing answers. Emulation still satisfies device detection (games
    /// configure and run); playback is dropped.
    EmulatedSilent,
}

impl Audio {
    /// Guest SB programming reaches a real card (vs the software DSP).
    pub fn sb_passthrough(self) -> bool {
        matches!(self, Audio::SbPassthrough)
    }
}

/// Where the filesystems come from — the probe result IS the mount plan
/// (`mount_filesystems` derives the mount set from the variant payload).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Media {
    /// A boot disk answered with an ext4 root (0x83) in its partition
    /// table: the natural root for metal (and hosted runs with an image
    /// attached). `hostfs` additionally at /host when the COM1 transport
    /// answered. (/boot is NOT from disk — the embedded bootfs is an
    /// invariant; the 0xDA boot-bundle partition is bootloader-only.)
    /// `extra_ext` holds additional ext partitions (a multi-distro disk has
    /// several); they mount as subdirectories C:\DISK1, C:\DISK2, … of the
    /// root. Unused slots are 0.
    DiskRoot { ext4_lba: u32, extra_ext: [u32; 3], hostfs: bool },
    /// No usable disk, but the host filesystem answered: it IS the root —
    /// the natural root for hosted runs (DOSBox-style: a host directory is
    /// the drive, no image build). Also aliased at /host so DiskRoot-era
    /// `host/...` paths keep working; /boot = the embedded bootfs.
    HostRoot,
    /// Neither: the embedded bootfs at /boot is the whole world (a bare
    /// kernel.elf booted from someone's GRUB).
    Diskless,
}

/// Where dbg_println bytes go. Installed by the backend long before startup
/// (boot prints need it); recorded here so policy can reason about it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DebugSink {
    /// Port 0xE9 debugcon (QEMU/Bochs `-debugcon`; harmlessly absent on
    /// real metal).
    #[cfg(not(feature = "hosted"))]
    Debugcon,
    /// The host process's stdout (hosted backend).
    #[cfg(feature = "hosted")]
    HostStdout,
}

impl Display {
    /// Guest VGA port programming reaches the real card (vs the VgaState
    /// register model).
    pub fn vga_passthrough(self) -> bool {
        // `VgaCard` only exists on metal (a hosted run never owns a real card),
        // so the predicate is constant-false there.
        #[cfg(feature = "hosted")]
        {
            let _ = self;
            false
        }
        #[cfg(not(feature = "hosted"))]
        {
            matches!(self, Display::VgaCard)
        }
    }
}

static mut PLATFORM: Option<Platform> = None;

/// Probe the machine and freeze the result. Called exactly once, early in
/// `startup` — after the heap, before threading (still single-threaded, so
/// the write-once static needs no lock).
pub fn probe(machine: &mut crate::TheArch, boot: &crate::BootConfig) -> &'static Platform {
    let audio = probe_audio(machine);
    let media = probe_media(machine);

    // Metal: ask the hardware. Hosted: the answers are properties of the
    // backend itself — the interp port bus has no VGA device and its zeroed
    // guest RAM never contains a ROM — and its guest address space doesn't
    // even exist yet this early, so there is nothing to probe.
    #[cfg(not(feature = "hosted"))]
    let p = {
        // A GOP linear framebuffer (fbcon active) IS the scanout the firmware
        // handed us, so it wins unconditionally — even when a legacy VGA card
        // also answers its I/O ports. On a UEFI machine the GPU still latches
        // the VGA sequencer/CRTC registers (so `vga_card_answers` is true), but
        // that register file no longer drives the panel; the GOP framebuffer
        // does. Probing VGA first mislabels the display as `VgaCard`, routes the
        // DOS guest's VGA programming through to those dead legacy registers,
        // and `display_tick` then skips the GOP present — DOS Navigator launched
        // on a UEFI laptop showed a blank/white panel while the kernel console
        // (rendered straight to GOP) was fine. Only when no framebuffer was
        // handed over (legacy-BIOS boot) does the real VGA card own the screen.
        let display = if crate::fbcon::active() {
            Display::Framebuffer
        } else if vga_card_answers() {
            Display::VgaCard
        } else {
            Display::Headless
        };

        // Every legacy BIOS has a far-JMP (0xEA) at the reset vector
        // F000:FFF0; a UEFI-booted machine (no CSM, nothing mapped at the
        // legacy ROM window) reads something else. The low-mem window is in
        // the kernel page tables from boot, so this read is always valid.
        let reset_vector =
            unsafe { core::ptr::read_volatile((crate::LOW_MEM_BASE + 0xFFFF0) as *const u8) };
        let firmware = if reset_vector == 0xEA {
            Firmware::NativeBios
        } else {
            Firmware::Substitute
        };

        Platform {
            host: if boot.is_qemu { Host::Qemu } else { Host::Metal },
            display,
            firmware,
            audio,
            media,
            debug: DebugSink::Debugcon,
        }
    };

    #[cfg(feature = "hosted")]
    let p = {
        let _ = boot;
        Platform {
            host: Host::Interp,
            display: if lib::vga_render::present_sink_installed() {
                Display::HostWindow
            } else {
                Display::Headless
            },
            firmware: Firmware::Substitute,
            audio,
            media,
            debug: DebugSink::HostStdout,
        }
    };

    unsafe {
        PLATFORM = Some(p);
    }
    let p = get();
    println!(
        "Platform: host={:?} display={:?} firmware={:?} audio={:?} media={:?} debug={:?}",
        p.host, p.display, p.firmware, p.audio, p.media, p.debug
    );
    p
}

/// The frozen platform description. Panics if `probe` has not run — an init
/// ordering bug that should be loud.
pub fn get() -> &'static Platform {
    unsafe {
        (&raw const PLATFORM)
            .as_ref()
            .unwrap()
            .as_ref()
            .expect("platform::get before platform::probe")
    }
}

/// The audio probe is uniform across backends: an absent ISA device reads
/// 0xFF (so no-SB is the same answer on the interpreter's port bus and on
/// card-less metal), PCI config reads are 0xFFFFFFFF where there is no PCI,
/// and the canonical port window answers its signature only where a backend
/// installed a sink. Card presence is machine-wide, so the probe uses the
/// canonical SB base 0x220 (a per-thread BLASTER override relocates the
/// guest-visible base, not the card).
fn probe_audio(machine: &mut crate::TheArch) -> Audio {
    let sb_absent = machine.inb(0x22C) == 0xFF && machine.inb(0x22E) == 0xFF;
    if !sb_absent {
        return Audio::SbPassthrough;
    }
    if crate::kernel::hda::scan(machine).is_some() {
        return Audio::EmulatedHda;
    }
    if crate::kernel::ac97::scan(machine).is_some() {
        return Audio::EmulatedAc97;
    }
    if crate::kernel::sound::window_present(machine) {
        return Audio::EmulatedPortWindow;
    }
    Audio::EmulatedSilent
}

/// True if sector 0 is a GPT *protective* MBR — a single entry of type 0xEE
/// covering the disk. GPT disks (every UEFI machine) put this at LBA 0 so
/// legacy tooling leaves the real layout alone; it also means the 0x83 scan
/// finds nothing, which is why a real laptop probes as Diskless.
fn is_protective_mbr(mbr: &[u8; 512]) -> bool {
    (0..4).any(|i| mbr[0x1BE + i * 16 + 4] == 0xEE)
}

/// Confirm the partition starting at `lba` is ext2/3/4 by its superblock magic:
/// 0xEF53 lives at byte 1080 of the partition (superblock at 1024, s_magic at
/// +0x38) → sector lba+2, offset 56. GUID-agnostic, so it catches any ext root
/// regardless of how the partition was typed.
fn is_ext_partition(lba: u32) -> bool {
    let mut sb = [0u8; 512];
    crate::kernel::block::read_sectors(lba + 2, &mut sb);
    u16::from_le_bytes([sb[56], sb[57]]) == 0xEF53
}

/// Walk the GPT and return the first-LBA of an ext* partition, or None.
///
/// LBA 1 holds the header (signature "EFI PART", then the partition-array LBA,
/// entry count and entry stride); the array follows. We read it a sector at a
/// time and probe each non-empty entry's superblock. Assumes 512-byte sectors
/// (the only size `block::read_sectors` handles — a 4K-formatted NVMe is
/// rejected earlier in the driver); partition starts past 4 GiB-sectors don't
/// fit our u32 LBA and are skipped, which never happens on a real laptop root.
fn gpt_collect_ext(out: &mut [u32]) -> usize {
    let mut hdr = [0u8; 512];
    crate::kernel::block::read_sectors(1, &mut hdr);
    if &hdr[0..8] != b"EFI PART" {
        return 0;
    }
    let entry_lba = u64::from_le_bytes(hdr[0x48..0x50].try_into().unwrap());
    let num_entries = u32::from_le_bytes(hdr[0x50..0x54].try_into().unwrap()).min(256) as usize;
    let entry_size = u32::from_le_bytes(hdr[0x54..0x58].try_into().unwrap()) as usize;
    // Standard entries are 128 bytes (4 per 512-byte sector) and never straddle
    // a sector. Bail on anything that doesn't divide a sector cleanly.
    if entry_size == 0 || entry_lba == 0 || entry_lba > u32::MAX as u64 || 512 % entry_size != 0 {
        return 0;
    }
    let per_sector = 512 / entry_size;
    let sectors = num_entries.div_ceil(per_sector);
    let mut buf = [0u8; 512];
    let mut n = 0;
    for s in 0..sectors {
        crate::kernel::block::read_sectors(entry_lba as u32 + s as u32, &mut buf);
        for e in 0..per_sector {
            let off = e * entry_size;
            // Type GUID all-zero ⇒ unused slot.
            if buf[off..off + 16].iter().all(|&b| b == 0) {
                continue;
            }
            let first_lba = u64::from_le_bytes(buf[off + 32..off + 40].try_into().unwrap());
            if first_lba == 0 || first_lba > u32::MAX as u64 {
                continue;
            }
            // Collect every ext* partition (a multi-distro disk has several);
            // the first becomes the root, the rest mount as subdirectories.
            if is_ext_partition(first_lba as u32) && n < out.len() {
                out[n] = first_lba as u32;
                n += 1;
            }
        }
    }
    n
}

/// Find the ext4 root and probe the hostfs COM1 transport. First the MBR (4
/// entries at 0x1BE, type 0x83 — the RetroOS image / legacy disks); if that's
/// empty and sector 0 is a GPT protective MBR (a real UEFI disk), walk the GPT
/// for an ext* partition instead. The 0xDA boot-bundle partition is the legacy
/// bootloader's business — the kernel ignores it. With no block device,
/// `read_sectors` leaves the buffer zeroed and every scan finds nothing — the
/// same verdict path as an empty disk.
/// Heuristic: does the ext partition at `lba` look like an actual Linux root
/// (has `/etc` and `/usr`) rather than a data partition? A multi-ext disk (a
/// laptop with a data partition AND the real root) gives no order guarantee, so
/// we sniff the layout to mount the right one at VFS /.
fn is_linux_root(lba: u32) -> bool {
    use crate::kernel::vfs::Filesystem;
    match crate::kernel::ext4fs::Ext4Fs::new(lba) {
        Ok(fs) => fs.dir_exists(b"etc") && fs.dir_exists(b"usr"),
        Err(_) => false,
    }
}

fn probe_media(machine: &mut crate::TheArch) -> Media {
    let _ = machine;
    let hostfs = crate::kernel::hostfs::init();

    let mut mbr = [0u8; 512];
    crate::kernel::block::read_sectors(0, &mut mbr);
    // Collect every ext partition on the disk (a dual-boot laptop has more than
    // one): MBR type 0x83 entries, or — on a real UEFI disk (protective MBR) —
    // the GPT's ext* partitions found by superblock magic.
    let mut parts = [0u32; 4];
    let mut n = 0;
    for i in 0..4 {
        let base = 0x1BE + i * 16;
        if mbr[base + 4] == 0x83 && n < parts.len() {
            parts[n] = u32::from_le_bytes(mbr[base + 8..base + 12].try_into().unwrap());
            n += 1;
        }
    }
    if n == 0 && is_protective_mbr(&mbr) {
        n = gpt_collect_ext(&mut parts);
    }

    if n > 0 {
        // A disk can carry several ext partitions (a data partition AND the
        // real Linux root); GPT/MBR order doesn't say which is the root. Mount
        // the one that looks like a Linux root (/etc + /usr) at VFS /; fall back
        // to the first if none matches (e.g. the RetroOS image's own ext4).
        let mut root_idx = 0;
        for (i, &p) in parts.iter().enumerate().take(n) {
            if is_linux_root(p) { root_idx = i; break; }
        }
        // The remaining ext partitions mount as C:\DISK1, C:\DISK2, …
        let mut extra_ext = [0u32; 3];
        let mut e = 0;
        for (i, &p) in parts.iter().enumerate().take(n) {
            if i != root_idx && e < extra_ext.len() {
                extra_ext[e] = p;
                e += 1;
            }
        }
        Media::DiskRoot { ext4_lba: parts[root_idx], extra_ext, hostfs }
    } else if hostfs {
        Media::HostRoot
    } else {
        Media::Diskless
    }
}

/// Is a real VGA card on the bus? Write the SEQ index register and read it
/// back — an absent ISA-bus port reads 0xFF.
#[cfg(not(feature = "hosted"))]
fn vga_card_answers() -> bool {
    use crate::arch::{inb, outb};
    let saved = inb(0x3C4);
    outb(0x3C4, 0x02);
    let present = inb(0x3C4) == 0x02;
    if present {
        outb(0x3C4, saved);
    }
    present
}
