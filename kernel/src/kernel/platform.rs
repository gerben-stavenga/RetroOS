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
    Metal,
    /// The hosted interpreter backend (arch-interp as a host process).
    Interp,
}

/// The display path. Exactly one of these is true, decided here — not
/// re-derived piecemeal by render/console/IOPB code.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Display {
    /// A real VGA card answered the SEQ-register probe: guests program the
    /// hardware directly (passthrough port window); console = VGA text.
    VgaCard,
    /// No card, but the loader handed over a linear framebuffer (UEFI/GOP):
    /// the kernel-emulated VGA renders through fbcon.
    Framebuffer,
    /// No card or framebuffer, but a host window installed a present sink
    /// (retroos-play): the emulated VGA renders into the window.
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
    /// A boot disk answered with a usable partition table: the natural
    /// root for metal (and hosted runs with an image attached). `tar_lba`
    /// = 0xDA boot-bundle TAR for /boot (embedded bootfs stands in when
    /// absent); `ext4_lba` = the 0x83 root. `hostfs` additionally at /host
    /// when the COM1 transport answered.
    DiskRoot { tar_lba: Option<u32>, ext4_lba: Option<u32>, hostfs: bool },
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
    Debugcon,
    /// The host process's stdout (hosted backend).
    HostStdout,
}

impl Display {
    /// Guest VGA port programming reaches the real card (vs the VgaState
    /// register model).
    pub fn vga_passthrough(self) -> bool {
        matches!(self, Display::VgaCard)
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
        let display = if vga_card_answers() {
            Display::VgaCard
        } else if crate::fbcon::active() {
            Display::Framebuffer
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
    if crate::kernel::ac97::scan(machine).is_some() {
        return Audio::EmulatedAc97;
    }
    if crate::kernel::sound::window_present(machine) {
        return Audio::EmulatedPortWindow;
    }
    Audio::EmulatedSilent
}

/// Scan the MBR (4 entries at 0x1BE) for the boot-bundle TAR (type 0xDA)
/// and the ext4 root (0x83), and probe the hostfs COM1 transport. With no
/// block device, `read_sectors` leaves the buffer zeroed and the scan finds
/// nothing — the same verdict path as an empty disk.
fn probe_media(machine: &mut crate::TheArch) -> Media {
    let _ = machine;
    let hostfs = crate::kernel::hostfs::init();

    let mut mbr = [0u8; 512];
    crate::kernel::block::read_sectors(0, &mut mbr);
    let mut tar_lba = None;
    let mut ext4_lba = None;
    for i in 0..4 {
        let base = 0x1BE + i * 16;
        let lba = u32::from_le_bytes(mbr[base + 8..base + 12].try_into().unwrap());
        match mbr[base + 4] {
            0xDA => tar_lba = Some(lba),
            0x83 => ext4_lba = Some(lba),
            _ => {}
        }
    }

    if tar_lba.is_some() || ext4_lba.is_some() {
        Media::DiskRoot { tar_lba, ext4_lba, hostfs }
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
