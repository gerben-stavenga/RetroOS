//! Kernel startup - filesystem mount and DN.COM loader

extern crate alloc;

use crate::Regs;
use crate::kernel::thread;
use crate::kernel::{
    fs::portable_ext4::PortableExt4Fs,
    vfs,
};

/// Startup: the kernel's ordered init spine — probe, then derive, then run.
/// Each phase is a named function below; this stays short enough to read as
/// the boot story. Called from enter_ring1 — we are already at ring 1.
pub fn startup<A: crate::Arch>(machine: &mut A, boot: &crate::BootConfig) -> ! {
    // The global allocator is installed by the binary glue before startup runs
    // (metal: `arch/boot.rs`; hosted: std), so heap-using code is safe here on.

    crate::println!("{}", crate::build_info::VersionBanner);

    // Discover every disk. The block layer reports what exists; nothing below
    // this line picks a boot disk or decides where anything mounts.
    let disks = crate::kernel::block::probe(machine);
    for d in &disks {
        crate::println!("Storage: {} ({} MB)", d.name(), d.sectors() / 2048);
    }
    if disks.is_empty() {
        crate::println!("Storage: none detected");
    }
    crate::println!("Block devices initialized");

    // Probe the machine ONCE and freeze the result; all hardware policy
    // (VGA passthrough, BIOS choice, audio, console, IOPB) derives from this.
    // It no longer touches storage — the mount decision is made below, from
    // the partition tables, by the layer that owns it.
    let crate::kernel::platform::ProbedPlatform {
        facts: platform,
        display,
        audio,
    } = crate::kernel::platform::probe(machine, boot);

    // Select the kernel display once, before anything draws through it.
    // Preserve a pristine real-mode environment for this and all later
    // firmware calls; DOS personalities receive their separate substitute BIOS.
    let mut bios_workspace = crate::kernel::bios_display::BiosDisplayWorkspace::new(machine);
    let vbe_mode = display
        .vga_capability()
        .and_then(|native| native.bios_discover_vbe(machine, &mut bios_workspace));
    crate::kernel::platform::set_vbe_mode(vbe_mode);
    crate::kernel::platform::set_voodoo_vbe_mode(
        bios_workspace.curated_modes(),
        !display.is_headless(),
    );
    let display = match display.into_native_capability(machine) {
        Ok(native) => {
            crate::kernel::display::Display::new_selected(machine, &mut bios_workspace, native)
        }
        Err(display) => display,
    };
    let mut screen = crate::kernel::console::Console::new(display);

    // Disk-write policy, applied by COMPOSITION and DECLARED, never inferred.
    //
    // RetroOS writes to its disk, like an operating system. A machine that
    // wants its medium left alone asks for it, with `ram-overlay` on the
    // kernel command line — and the machine that wants it is the one with a
    // real install on it, which boots through GRUB, whose config its owner
    // controls. So the protection is configured where the risk actually lives.
    //
    // It used to be the other way round: protect by default, on the theory
    // that metal means "someone's real disk". That silently broke every
    // emulator too — a DOS program could not save a game, and a test could not
    // leave a verdict behind, which is why the 86Box SB suite could assert
    // nothing for as long as it existed. The first repair was worse: sniff the
    // southbridge and call a PIIX-class chipset an emulator. That gets this
    // project's own audience exactly backwards, since a real Pentium with a
    // PIIX4 is a first-class target and the likeliest machine to be holding
    // someone's actual data. No heuristic can answer "is this disk precious";
    // only its owner can, so only its owner does.
    //
    // Done before partition scanning, so every Volume built below already
    // carries the policy.
    let disks = if boot.ram_overlay {
        crate::screenln!(
            screen,
            "Disk writes: volatile RAM overlay (ram-overlay) — changes will NOT persist"
        );
        disks
            .into_iter()
            .map(|d| -> &'static dyn crate::kernel::block::Disk {
                alloc::boxed::Box::leak(alloc::boxed::Box::new(
                    crate::kernel::block::overlay::RamOverlay::wrap(d),
                ))
            })
            .collect()
    } else {
        // One line, because there is one behaviour. This used to print a
        // different message per host — a leftover from when the host DERIVED
        // the policy. It no longer does: the policy is `ram-overlay` or its
        // absence, and whether the device underneath is a laptop's NVMe or a
        // disposable image is not something the kernel knows or should claim.
        crate::screenln!(
            screen,
            "\x1b[91mDisk writes: PERSISTENT\x1b[0m — pass `ram-overlay` to protect the disk"
        );
        disks
    };
    // The thread table is a plain owned Vec now (fixed MAX_THREADS slots,
    // reused) — startup owns it and threads `&mut threads` down through run →
    // run_program → event_loop. No global; no `&'static mut`.
    let mut threads = crate::kernel::thread::init_threading();
    crate::screenln!(screen => machine, &mut bios_workspace; "Threading initialized");

    // FS-layout policy (DOS C: → VFS subtree) before any mount/resolve.
    crate::kernel::dos::set_c_root(boot.c_root());
    crate::kernel::dos::set_hostfs_enabled(platform.hostfs);

    // Read every disk's partition table, then decide the mount tree from what
    // they declare. `plan_mounts` is a pure function of those facts.
    crate::screenln!(screen => machine, &mut bios_workspace;
        "Filesystems: scanning partition tables...");
    let parts: alloc::vec::Vec<_> = disks
        .iter()
        .flat_map(|&d| {
            crate::kernel::block::partition::scan(crate::kernel::block::Volume::whole(d))
        })
        .collect();
    crate::screenln!(screen => machine, &mut bios_workspace;
        "Filesystems: {} partition(s) found", parts.len());
    let modules = crate::multiboot::mount_modules(boot, &mut screen, 0);
    let hostfs_is_root = mount_filesystems(
        machine,
        &mut bios_workspace,
        &parts,
        platform.hostfs,
        &mut screen,
        modules,
    );
    screen.present(machine, &mut bios_workspace);
    // A root mount must have an established backend/session. Later filesystem
    // operations retain their normal operation-driven reconnect behavior.
    if hostfs_is_root && !crate::kernel::fs::hostfs::is_ready() {
        panic!("hostfs: mounted as root but its server is unavailable");
    }
    // Permanent empty proxies keep the mount table stable while the OSD
    // inserts/ejects images discovered under DOS's C:\CD and C:\FLOPPY.
    crate::kernel::fs::cdrom::init();
    crate::kernel::fs::floppy::init();

    // CONFIG.SYS is readable now: apply its sound-mode policy before anything
    // consumes the verdict (IOPB grants, the bank burn, the first guest).
    // `SB_AUDIO=native|mixed`; QEMU's `-fw_cfg opt/audio=mixed` overrides it
    // for testing without editing the disk.
    let master_env = load_master_env();
    crate::kernel::drivers::hda::configure_output_route(crate::kernel::dos::config_var(
        &master_env,
        b"HDA_OUTPUT",
    ));
    crate::kernel::osd::configure_master_volume(crate::kernel::dos::config_var(
        &master_env,
        b"AUDIO_VOLUME",
    ));
    let sb_audio = crate::kernel::dos::config_var(&master_env, b"SB_AUDIO")
        .map(alloc::vec::Vec::from)
        .unwrap_or_default();
    let mixed = boot.audio_mixed
        || sb_audio
            .split(|&b| b == b' ')
            .next()
            .is_some_and(|m| m.eq_ignore_ascii_case(b"mixed"));
    // Mints the machine's one Sound Blaster, if it has a drivable one. We hold
    // it while reconciling it against BLASTER, then leave it unclaimed for
    // whichever owner the mode selected to take.
    let sb_card =
        crate::kernel::platform::apply_audio_mode(machine, mixed, parse_sb_wiring(&sb_audio));
    let platform = crate::kernel::platform::get();

    // BLASTER describes THE CARD THE GUEST SEES.
    //
    //   mixed  — that card is our emulated SB16, so CONFIG.SYS's BLASTER
    //            stands verbatim: the owner picks whatever settings their
    //            games are configured for. (The real card's own wiring is
    //            the sink driver's business, read from its mixer.)
    //   native — that card is the physical one, so BLASTER is fabricated
    //            from what the card reported. An SB16 reports its own
    //            IRQ/DMA; below DSP 4 those straps are invisible to
    //            software and the owner declares them on the SB_AUDIO line
    //            (`SB_AUDIO=native <irq> <dma8>`). Nothing is guessed — a
    //            wrong IRQ silently swallows every completion.
    // BLASTER is authoritative in both modes — it declares the card the
    // guest sees, and the owner sets it to whatever their games expect.
    //
    // In MIXED mode that card is ours, so every value is honoured as-is.
    //
    // In NATIVE mode the guest drives real silicon, and only one of those
    // values is physical: the PORT is granted through the IOPB, so the
    // guest's writes land wherever BLASTER points — the card's base or
    // nothing at all. IRQ and DMA are labels the machine translates (the
    // card's line is relayed onto the guest's vPIC line, its 8237 channels
    // are remapped onto the card's), so those stay free. We verify rather
    // than rewrite: a mismatch is the owner's to fix, and silently
    // "correcting" it would break the games whose own configs agree with
    // CONFIG.SYS.
    let mut sb_card = sb_card;
    if platform.audio == crate::kernel::platform::Audio::NativeSb
        && let Some(card) = sb_card.as_mut()
    {
        let blaster = crate::kernel::dos::config_var(&master_env, b"BLASTER")
            .map(alloc::vec::Vec::from)
            .unwrap_or_default();
        match blaster_base(&blaster) {
            Some(b) if b == card.base => {}
            Some(b) => crate::println!(
                "Audio: BLASTER declares A{:03X}, the card answers at {:#05X} — translating (the \
                 DSP window traps anyway, so the guest sees its declared card)",
                b,
                card.base
            ),
            None => crate::println!(
                "Audio: no BLASTER port declared, card is at {:#05X}",
                card.base
            ),
        }
        // An SB16's IRQ/DMA are soft-straps (mixer 0x80/0x81) — and NOT just
        // routing labels: the 0x81 high bits ENABLE the 16-bit DMA channel.
        // Bochs's SB16 powers up without one ("DMA 1/0"), so a guest's
        // 16-bit auto-init never moves and its position poll spins for the
        // whole intro (Pinball Fantasies). Strap the card to BLASTER; the
        // relay/remap then act on what the card really accepted (readback).
        // NOT on QEMU: its sb16 is launched deliberately misaligned (run.sh
        // irq=5) as permanent relay/remap coverage, and its mixer accepts
        // the strap write without rerouting the actual line. The guest can
        // never undo this: the mixer pair always traps (vsb::trap_mask).
        if crate::kernel::platform::get().host != crate::kernel::platform::Host::Qemu
            && let Some(want) = blaster_wiring(&blaster)
            && card.wiring() != want
        {
            let got = card.restrap(machine, want);
            let h = |d: Option<u8>| d.map(|v| alloc::format!(" HDMA{}", v)).unwrap_or_default();
            if got == want {
                crate::println!(
                    "Audio: SB16 restrapped to BLASTER (IRQ{} DMA{}{})",
                    got.irq,
                    got.dma8,
                    h(got.dma16)
                );
            } else {
                crate::println!(
                    "Audio: SB16 kept IRQ{} DMA{}{} (strap write refused) — relaying to \
                     BLASTER's IRQ{} DMA{}",
                    got.irq,
                    got.dma8,
                    h(got.dma16),
                    want.irq,
                    want.dma8
                );
            }
        }
        // Only a DOS-owned native SB needs its hardware IRQ. Mixer ownership
        // polls DMA position, so routing its completion line would create a
        // wakeup and acknowledgement path with no accounting purpose.
        if matches!(platform.audio, crate::kernel::platform::Audio::NativeSb) {
            machine.route_isa_irq(card.irq);
            crate::println!("Audio: SB IRQ{} routed", card.irq);
        }

        // Judge the H-declaration against the acting straps — the restrap just
        // above may have enabled the 16-bit channel.
        if card.dma16.is_none()
            && blaster
                .split(|&b| b == b' ')
                .any(|t| t.first().is_some_and(|c| c.eq_ignore_ascii_case(&b'H')))
        {
            crate::println!("Audio: BLASTER declares a 16-bit channel but this card has none");
        }
    }
    // Reconciliation done: settle who the card belongs to. In mixer mode the
    // sink takes it and keeps it; otherwise the sink is built without one and
    // the card travels — into whichever DOS thread holds the console, and back
    // out when that thread gives up focus or exits, exactly as the display
    // token does.
    let for_sink = (platform.audio == crate::kernel::platform::Audio::SbSink)
        .then(|| sb_card.take())
        .flatten();

    // Burn the GM bank ROM while long work is still legal (no guest yet):
    // the shipped bank lives under the C: root beside the GUS patches. A
    // native-SB machine has no emulated GM to feed and cannot afford the
    // ~5 MB; a silent machine has nothing to render it to.
    match platform.audio {
        crate::kernel::platform::Audio::NativeSb
        | crate::kernel::platform::Audio::EmulatedSilent => {}
        _ => {
            crate::screenln!(screen => machine, &mut bios_workspace;
                "Loading General MIDI bank...");
            crate::kernel::midi_bank::load_from_c_root(crate::kernel::dos::c_root());
            crate::screenln!(screen => machine, &mut bios_workspace;
                "General MIDI bank load complete");
        }
    }
    // Take the selected output capability into runtime ownership. `None` is a
    // silent runtime, not a dummy sink.
    let sink = crate::kernel::sound::Sink::new(machine, audio, for_sink);
    init_console_pipe();

    // DOS worlds are cloned from their substitute-BIOS template.
    let mut dos_template = crate::kernel::dos::DosTemplate::new(machine);

    run(
        machine,
        boot,
        &master_env,
        &mut bios_workspace,
        &mut dos_template,
        &mut threads,
        screen,
        sb_card,
        sink,
    )
}

/// The host filesystem on the selected serial transport. Mounted at /host
/// beside a disk root, or as the root when no other root is available.
static HOSTFS: crate::kernel::fs::hostfs::HostFs = crate::kernel::fs::hostfs::HostFs::new();

/// The host fs to mount: the injected native `std::fs` backend when the entry
/// installed one (hosted "punch-through" — direct calls, no serial), else the
/// selected-port `HOSTFS` client (metal / the Python bridge).
fn host_fs() -> &'static dyn vfs::Filesystem {
    if crate::kernel::fs::hostfs::host_backend_installed() {
        &crate::kernel::fs::hostfs::INJECTED_HOSTFS
    } else {
        &HOSTFS
    }
}

/// Keep the boot-time mount namespace in the single-digit `/diskN` range.
const MAX_EXT_MOUNTS: usize = 8;

/// Which ext filesystem is the root: the one that looks like a Linux root
/// (`/etc` + `/usr`), else the first.
///
/// This is the ONLY real decision in the mount tree — everything else follows
/// mechanically — so it is the only part worth naming. A disk can carry
/// several ext partitions (a data partition AND the real root) and the table
/// order says nothing about which is which. Only sniff when ambiguous: a lone
/// ext partition IS the root, and probing it would mean a needless mount.
fn root_index(ext: &[crate::kernel::block::Volume]) -> usize {
    if ext.len() < 2 {
        return 0;
    }
    ext.iter()
        .position(crate::kernel::fs::portable_ext4::is_linux_root)
        .unwrap_or(0)
}

/// Build the mount tree. The disk's 0xDA boot-bundle partition is
/// bootloader-only and never mounted; C:\BOOT (DN + COMMAND.COM) is an
/// ordinary directory on whatever backs C:, not a mount of its own.
fn mount_filesystems<A: crate::Arch>(
    machine: &mut A,
    bios_workspace: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    parts: &[crate::kernel::block::partition::Partition],
    hostfs: bool,
    screen: &mut crate::kernel::console::Console,
    modules: crate::multiboot::ModuleMountSummary,
) -> bool {
    use crate::kernel::block::partition::PartKind;

    // Ask the filesystem, don't trust the table: a partition holds ext when it
    // has an ext superblock, whatever type byte or GUID it carries.
    crate::screenln!(screen => machine, bios_workspace;
        "Filesystems: probing ext superblocks...");
    let ext: alloc::vec::Vec<_> = parts
        .iter()
        .filter(|p| p.kind != PartKind::BootBundle)
        .map(|p| p.volume)
        .map(crate::kernel::block::cache::volume)
        .filter(crate::kernel::fs::portable_ext4::is_ext)
        .collect();
    crate::screenln!(screen => machine, bios_workspace;
        "Filesystems: {} ext partition(s)", ext.len());

    let mut hostfs_is_root = false;
    if modules.has_root {
        // A Multiboot root owns `/`; physical filesystems remain available as
        // read-only fallback mounts below `/diskN`.
        crate::multiboot::mount_physical_fallbacks(
            &ext,
            modules.next_ext_slot,
            MAX_EXT_MOUNTS,
            screen,
        );
        if hostfs {
            vfs::mount(b"host/", host_fs());
            crate::screenln!(screen, "hostfs: mounted at /host");
        }
    } else if ext.is_empty() {
        // No module or disk filesystem: the host fs is the root if available.
        if hostfs {
            vfs::mount(b"", host_fs());
            // Keep the DOS H: mapping stable even when hostfs is also `/`.
            vfs::mount(b"host/", host_fs());
            crate::screenln!(screen, "hostfs: mounted as root");
            hostfs_is_root = true;
        } else {
            panic!("No root filesystem available");
        }
    } else {
        let root = root_index(&ext);
        crate::screenln!(screen => machine, bios_workspace;
            "Mounting ext4 root ({} MB)...", ext[root].sectors / 2048);
        let fs = PortableExt4Fs::new(ext[root])
            .unwrap_or_else(|error| panic!("portable ext4 root mount failed: {}", error));
        crate::screenln!(screen => machine, bios_workspace; "ext4 root mounted");
        let fs: &'static dyn vfs::Filesystem =
            alloc::boxed::Box::leak(alloc::boxed::Box::new(fs));
        // The write grant is RetroOS's identity — the group owning its
        // home. C: is a DOS-side notion only this layer knows, and the
        // VFS enforces the rule from here on. Extra mounts get no
        // grant, so nothing on them is writable.
        vfs::mount_writable(b"", fs, crate::kernel::dos::c_root());

        // Every other ext filesystem mounts read-only at /disk1, /disk2, …
        // (Linux-visible, not under C:). An unreadable one is logged and
        // skipped, never fatal — the root is already up.
        let mut slot = modules.next_ext_slot;
        for (i, &vol) in ext.iter().enumerate() {
            if i == root {
                continue;
            }
            slot += 1;
            if slot >= MAX_EXT_MOUNTS {
                // Never drop a filesystem silently — say how many and why.
                crate::println!(
                    "ext4: {} further partition(s) not mounted (limit {})",
                    ext.len() - slot,
                    MAX_EXT_MOUNTS
                );
                break;
            }
            let mut prefix = alloc::vec::Vec::new();
            prefix.extend_from_slice(b"disk");
            prefix.push(b'0' + slot as u8);
            prefix.push(b'/');
            let prefix: &'static [u8] = alloc::boxed::Box::leak(prefix.into_boxed_slice());
            match PortableExt4Fs::new(vol) {
                Ok(fs) => {
                    vfs::mount(prefix, alloc::boxed::Box::leak(alloc::boxed::Box::new(fs)));
                    crate::screenln!(
                        screen,
                        "portable ext4 partition ({} MB) → /disk{}",
                        vol.sectors / 2048,
                        slot
                    );
                }
                Err(error) => crate::screenln!(screen, "ext4 partition skipped: {}", error),
            }
        }

        if hostfs {
            vfs::mount(b"host/", host_fs());
            crate::screenln!(screen, "hostfs: mounted at /host");
        }
    }

    // C:\BOOT is an ordinary directory on whatever backs C: — no mount, no
    // embedded archive. A root without one simply has no DOS system directory.
    mount_kernel_log_fs();

    crate::kernel::stacktrace::init_from_vfs();
    hostfs_is_root
}

fn mount_kernel_log_fs() {
    vfs::mount_union(b"proc/", &crate::kernel::klog::KLOG_FS);

    let c_root = crate::kernel::dos::c_root();
    if !c_root.is_empty() {
        let dos_proc_prefix: &'static [u8] =
            alloc::boxed::Box::leak([c_root, b"proc/"].concat().into_boxed_slice());
        vfs::mount_union(dos_proc_prefix, &crate::kernel::klog::KLOG_FS);
    }
}

/// /CONFIG.SYS provides the master env handed to DN and any user-driven
/// launches. KEY=VALUE lines, `#` comments. One location, C:\CONFIG.SYS —
/// the second lookup existed only for the embedded bootfs's fallback copy.
/// Absent, the env is empty.
fn load_master_env() -> alloc::vec::Vec<u8> {
    let user_cfg = [crate::kernel::dos::c_root(), b"CONFIG.SYS"].concat();
    let config = crate::kernel::exec::load_file_resolved(&user_cfg).unwrap_or_default();
    crate::kernel::dos::parse_config_env(&config)
}

/// `SB_AUDIO=native <irq> <dma8>` — the wiring an owner declares for a card
/// that cannot report its own (pre-SB16). `None` when absent or malformed.
fn parse_sb_wiring(v: &[u8]) -> Option<crate::kernel::drivers::sb16::SbWiring> {
    let mut it = v.split(|&b| b == b' ').filter(|t| !t.is_empty()).skip(1);
    let irq = parse_u8(it.next()?)?;
    let dma8 = parse_u8(it.next()?)?;
    Some(crate::kernel::drivers::sb16::SbWiring {
        irq,
        dma8,
        dma16: None,
    })
}

fn parse_u8(s: &[u8]) -> Option<u8> {
    let mut n: u32 = 0;
    for &b in s {
        if !b.is_ascii_digit() {
            return None;
        }
        n = n * 10 + (b - b'0') as u32;
    }
    (!s.is_empty() && n < 256).then_some(n as u8)
}

/// The `A` token of a BLASTER string, as a port number.
fn blaster_base(v: &[u8]) -> Option<u16> {
    for tok in v.split(|&b| b == b' ').filter(|t| !t.is_empty()) {
        if tok[0].eq_ignore_ascii_case(&b'A') {
            let mut n: u16 = 0;
            for &c in &tok[1..] {
                n = n * 16 + (c as char).to_digit(16)? as u16;
            }
            return Some(n);
        }
    }
    None
}

/// BLASTER's I/D/H tokens as a wiring triple — what the owner wants the card
/// strapped to. None if I or D is missing (H is optional: pre-SB16 declares).
fn blaster_wiring(v: &[u8]) -> Option<crate::kernel::drivers::sb16::SbWiring> {
    let mut irq = None;
    let mut dma8 = None;
    let mut dma16 = None;
    for tok in v.split(|&b| b == b' ').filter(|t| !t.is_empty()) {
        let num = || -> Option<u8> {
            let mut n: u8 = 0;
            for &c in &tok[1..] {
                n = n
                    .checked_mul(10)?
                    .checked_add((c as char).to_digit(10)? as u8)?;
            }
            Some(n)
        };
        match tok[0].to_ascii_uppercase() {
            b'I' => irq = num(),
            b'D' => dma8 = num(),
            b'H' => dma16 = num(),
            _ => {}
        }
    }
    Some(crate::kernel::drivers::sb16::SbWiring {
        irq: irq?,
        dma8: dma8?,
        dma16,
    })
}

/// Allocate the console stdin pipe (keyboard → Linux stdin). The kernel
/// itself is the writer (via process_key during the event loop drain), so
/// register a phantom writer permanently — without it, has_writers returns
/// false and the first read on fd 0 reports EOF immediately, which makes
/// busybox/sh bail out at startup.
fn init_console_pipe() {
    let console_pipe = crate::kernel::kpipe::alloc().expect("Failed to allocate console pipe");
    crate::kernel::kpipe::add_writer(console_pipe);
    crate::kernel::thread::set_console_pipe(console_pipe);
}

/// Run what the boot asked for: the headless `-fw_cfg opt/cmdline` program
/// sequence (shut down after), or the interactive DN loop.
fn is_kernel_launch_directive(key: &[u8]) -> bool {
    arch_abi::cmdline::key_eq(key, b"hostfs")
        || arch_abi::cmdline::key_eq(key, b"serial")
}

#[cfg(test)]
mod launch_directive_tests {
    use super::is_kernel_launch_directive;

    #[test]
    fn serial_directive_is_not_treated_as_a_program() {
        let segment = arch_abi::cmdline::segments(b"serial=com2;TESTS/X.COM arg")
            .nth(1)
            .unwrap();
        let launch = arch_abi::cmdline::launch(segment, is_kernel_launch_directive).unwrap();
        assert_eq!(launch.program(), b"TESTS/X.COM");
        let mut args = [0u8; 8];
        let len = launch.write_arguments(&mut args);
        assert_eq!(&args[..len], b"arg");
    }
}

#[allow(clippy::too_many_arguments)]
fn run<A: crate::Arch>(
    machine: &mut A,
    boot: &crate::BootConfig,
    master_env: &[u8],
    bios_workspace: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    dos_template: &mut crate::kernel::dos::DosTemplate<A>,
    threads: &mut [thread::Thread<A>],
    mut screen: crate::kernel::console::Console,
    mut sb: Option<crate::kernel::drivers::sb16::SbCard>,
    mut sink: Option<crate::kernel::sound::Sink>,
) -> ! {
    // What to run headlessly, from whichever channel the backend has. QEMU and
    // the hosted interpreter pass a cmdline through `opt/cmdline`; 86Box and
    // Bochs have NO such channel — `--cmd` was silently ignored there, so every
    // "probe run" on the one backend that models a real SB16 faithfully booted
    // the normal image and sat at DN. `TEST=` in CONFIG.SYS is the channel that
    // needs no hypervisor cooperation: it travels in the image, so it works on
    // every backend and on real metal too. Same sequence, same shutdown after.
    let cmdline = boot
        .cmdline()
        .or_else(|| crate::kernel::dos::config_var(master_env, b"TEST"));
    if let Some(raw) = cmdline {
        // CWD: explicit `opt/cwd` key wins; else fall back to each program's
        // own directory.
        let explicit_cwd = boot.cwd().map(trim_ascii);

        for segment in arch_abi::cmdline::segments(raw) {
            let Some(launch) = arch_abi::cmdline::launch(segment, is_kernel_launch_directive)
            else {
                continue;
            };
            let path = launch.program();

            // Build the DOS PSP tail from the filtered token stream. The
            // protocol reserves 126 bytes for the tail; Psp::set_cmdline
            // applies the same bound when installing it.
            let mut tail_buf = [0u8; 126];
            let tail_len = launch.write_arguments(&mut tail_buf);
            let tail = &tail_buf[..tail_len];

            let cwd: &[u8] = match explicit_cwd {
                Some(c) => c,
                None => {
                    let cwd_end = path.iter().rposition(|&b| b == b'/').map_or(0, |i| i + 1);
                    &path[..cwd_end]
                }
            };
            crate::screenln!(
                screen,
                "Starting {} {} (cwd={})...",
                core::str::from_utf8(path).unwrap_or("?"),
                core::str::from_utf8(tail).unwrap_or(""),
                core::str::from_utf8(cwd).unwrap_or("?")
            );
            (screen, sb) = run_program_with_screen(
                machine,
                bios_workspace,
                dos_template,
                threads,
                path,
                tail,
                cwd,
                master_env,
                boot.debug_watch,
                screen,
                sb,
                sink.as_mut(),
            );
        }
        crate::screenln!(screen, "All commands done — shutting down.");
        crate::kernel::drivers::hda::emergency_quiesce(); // codec must not ride into poweroff unparked
        machine.shutdown();
    }

    // COMMAND.COM is prebuilt (in-OS TCC at image-build time —
    // //tools/command:command_com) and ships at C:\BOOT\COMMAND.COM, which is
    // where COMSPEC points. The per-boot self-build from
    // BOOT\SRC\COMMAND.C is gone with it; the BCC EXEC-path exercise it
    // doubled as lives on in test/dpmi_smoke.sh.

    crate::screenln!(screen, "Welcome to RetroOS! F12 opens the host monitor.");

    crate::screenln!(screen, "Starting DN...");
    let dn_path = [crate::kernel::dos::c_root(), b"BOOT/DN/DN.COM"].concat();
    loop {
        (screen, sb) = run_program_with_screen(
            machine,
            bios_workspace,
            dos_template,
            threads,
            &dn_path,
            b"",
            b"",
            master_env,
            boot.debug_watch,
            screen,
            sb,
            sink.as_mut(),
        );
        crate::screenln!(screen, "DN exited, restarting...");
    }
}

#[allow(clippy::too_many_arguments)]
fn run_program_with_screen<A: crate::Arch>(
    machine: &mut A,
    bios_workspace: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    dos_template: &mut crate::kernel::dos::DosTemplate<A>,
    threads: &mut [thread::Thread<A>],
    path: &[u8],
    cmdline_tail: &[u8],
    cwd: &[u8],
    env: &[u8],
    debug_watch: Option<(u32, u32)>,
    screen: crate::kernel::console::Console,
    sb: Option<crate::kernel::drivers::sb16::SbCard>,
    sink: Option<&mut crate::kernel::sound::Sink>,
) -> (
    crate::kernel::console::Console,
    Option<crate::kernel::drivers::sb16::SbCard>,
) {
    let (card, display) = screen.release(machine, bios_workspace);
    let (display, sb) = run_program(
        machine,
        bios_workspace,
        dos_template,
        threads,
        path,
        cmdline_tail,
        cwd,
        env,
        debug_watch,
        display,
        sb,
        sink,
    );
    (
        crate::kernel::console::Console::acquire(machine, card, display),
        sb,
    )
}

/// Load and run a single cmdline program until it exits. ELF binaries run
/// through the Linux loader (a fresh process thread); `.COM` / MZ `.EXE`
/// through the DOS VM86 loader. `cmdline_tail`/`env` apply only to the DOS
/// path (PSP:0080h cmdline + environment).
#[allow(clippy::too_many_arguments)]
fn run_program<A: crate::Arch>(
    machine: &mut A,
    bios_workspace: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    dos_template: &mut crate::kernel::dos::DosTemplate<A>,
    threads: &mut [thread::Thread<A>],
    path: &[u8],
    cmdline_tail: &[u8],
    cwd: &[u8],
    env: &[u8],
    debug_watch: Option<(u32, u32)>,
    display: crate::kernel::display::Display,
    sb: Option<crate::kernel::drivers::sb16::SbCard>,
    sink: Option<&mut crate::kernel::sound::Sink>,
) -> (
    crate::kernel::display::Display,
    Option<crate::kernel::drivers::sb16::SbCard>,
) {
    use crate::kernel::{dos, exec};

    // A cmdline path is user-facing: accept both a full VFS path and a DOS
    // C:-relative one (the common `--cmd GAMES/...` form — C: = c_root, same
    // resolution the DOS personality applies to the program's own file I/O).
    let buf = exec::load_file_resolved(path)
        .or_else(|_| exec::load_file_resolved(&[crate::kernel::dos::c_root(), path].concat()))
        .unwrap_or_else(|_| panic!("{} not found", core::str::from_utf8(path).unwrap_or("?")));
    // argv = path + the cmdline tail split into words. The ELF/Linux path
    // consumes the full argv (`--cmd "/usr/bin/dash -c 'echo hi'"` must reach
    // dash as ["-c", "echo hi"]); DOS ignores the extra entries and gets the
    // raw tail as PSP:0080h instead. Quotes group words, nothing more — the
    // launcher is not a shell.
    let mut args = alloc::vec![path.to_vec()];
    {
        let mut word: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        let mut quote: u8 = 0;
        for &b in cmdline_tail {
            match b {
                b'\'' | b'"' if quote == 0 => quote = b,
                b if quote != 0 && b == quote => quote = 0,
                b' ' if quote == 0 => {
                    if !word.is_empty() {
                        args.push(core::mem::take(&mut word));
                    }
                }
                b => word.push(b),
            }
        }
        if !word.is_empty() {
            args.push(word);
        }
    }
    let cmdline_tail = cmdline_tail.to_vec();
    let cwd = cwd.to_vec();
    let env = env.to_vec();

    // No screen handoff bookkeeping: on-screen kernel text requires the
    // `Console` value, which our caller holds and does not touch until this
    // program's world ends — so kernel logs cannot trample user-space pixel
    // data when the program is in graphics mode (CGA modes use B8000 as a
    // pixel framebuffer, identical address to text-mode char+attr storage).
    // dos_putchar's direct VGA writes are the program's own output, not
    // kernel text, and keep working for text-mode programs.

    machine.set_debug_watch(None);

    // Format-detect: protected-mode native formats get their personalities;
    // everything else is DOS. (The
    // cmdline launcher used to force every program through the DOS loader,
    // which silently load_com'd an ELF and ran its header as VM86 garbage.)
    let tid = match exec::detect_format(&buf, path) {
        exec::BinaryFormat::Elf => launch_elf(machine, threads, buf, path, args),
        exec::BinaryFormat::Lx => launch_os2(machine, threads, buf, path),
        exec::BinaryFormat::Ne => launch_win16(machine, threads, buf, path),
        exec::BinaryFormat::Pe => launch_windows(machine, threads, buf, path),
        _ => dos::run_init_program(
            machine,
            dos_template,
            threads,
            buf,
            args,
            cmdline_tail,
            cwd,
            env,
        ),
    };

    // The initial program owns the console outright (nothing to repaint) and
    // gets its port permissions from policy, not from boot-time leftovers.
    crate::kernel::focus::adopt(tid);
    let display = {
        let t = thread::get_thread(threads, tid).expect("init program thread");
        t.kernel.set_comm(path); // name the boot program for the F12 picker
        t.personality
            .adopt_display(machine, bios_workspace, display)
    };

    if let Some((addr0, addr1)) = debug_watch {
        machine.set_debug_watch(Some((addr0, addr1)));
        if addr1 != 0 {
            crate::dbg_println!(
                "[WATCH] armed write watchpoints at {:08X} and {:08X}",
                addr0,
                addr1
            );
        } else {
            crate::dbg_println!("[WATCH] armed write watchpoint at {:08X}", addr0);
        }
    }
    event_loop(machine, bios_workspace, threads, tid, sb, sink, display)
}

/// Launch an ELF as a fresh Linux process thread and return its tid: stdin is
/// the shared console pipe, stdout/stderr go to the console — mirroring the
/// hosted bare-ELF path (`host_run_elf`). The fresh empty address space is
/// already clean, so the ELF loader can write straight into it.
fn launch_elf<A: crate::Arch>(
    machine: &mut A,
    threads: &mut [thread::Thread<A>],
    buf: alloc::vec::Vec<u8>,
    path: &[u8],
    args: alloc::vec::Vec<alloc::vec::Vec<u8>>,
) -> usize {
    let cpipe = thread::console_pipe();
    let tid = {
        let t = thread::create_thread(threads, machine, None, A::PageTable::default(), true)
            .expect("create ELF thread");
        t.kernel.fds[0] = thread::FdKind::PipeRead(cpipe);
        t.kernel.fds[1] = thread::FdKind::ConsoleOut;
        t.kernel.fds[2] = thread::FdKind::ConsoleOut;
        t.kernel.tid as usize
    };
    crate::kernel::kpipe::add_reader(cpipe);
    crate::kernel::linux::exec_elf_into(machine, threads, tid, &buf, path, &args).unwrap_or_else(
        |e| {
            panic!(
                "ELF exec failed ({}): errno {}",
                core::str::from_utf8(path).unwrap_or("?"),
                e
            )
        },
    );
    tid
}

/// Launch a native 32-bit OS/2 LX image as a fresh process.
fn launch_os2<A: crate::Arch>(
    machine: &mut A,
    threads: &mut [thread::Thread<A>],
    buf: alloc::vec::Vec<u8>,
    path: &[u8],
) -> usize {
    let cpipe = thread::console_pipe();
    let tid = {
        let t = thread::create_thread(threads, machine, None, A::PageTable::default(), true)
            .expect("create OS/2 thread");
        t.kernel.fds[0] = thread::FdKind::PipeRead(cpipe);
        t.kernel.fds[1] = thread::FdKind::ConsoleOut;
        t.kernel.fds[2] = thread::FdKind::ConsoleOut;
        t.kernel.tid as usize
    };
    crate::kernel::kpipe::add_reader(cpipe);
    crate::kernel::os2::exec_lx_into(machine, threads, tid, buf, path, b"", None).unwrap_or_else(
        |e| {
            panic!(
                "OS/2 LX exec failed ({}): errno {}",
                core::str::from_utf8(path).unwrap_or("?"),
                e
            )
        },
    );
    tid
}

/// Launch a native 32-bit Windows PE image as a fresh process.
fn launch_windows<A: crate::Arch>(
    machine: &mut A,
    threads: &mut [thread::Thread<A>],
    buf: alloc::vec::Vec<u8>,
    path: &[u8],
) -> usize {
    let cpipe = thread::console_pipe();
    let tid = {
        let t = thread::create_thread(threads, machine, None, A::PageTable::default(), true)
            .expect("create Windows thread");
        t.kernel.fds[0] = thread::FdKind::PipeRead(cpipe);
        t.kernel.fds[1] = thread::FdKind::ConsoleOut;
        t.kernel.fds[2] = thread::FdKind::ConsoleOut;
        t.kernel.tid as usize
    };
    crate::kernel::kpipe::add_reader(cpipe);
    crate::kernel::windows::exec_pe_into(machine, threads, tid, buf, path, b"", None)
        .unwrap_or_else(|e| {
            panic!(
                "Windows PE exec failed ({}): errno {}",
                core::str::from_utf8(path).unwrap_or("?"),
                e
            )
        });
    tid
}

/// Launch a native 16-bit Windows NE image as a fresh process.
fn launch_win16<A: crate::Arch>(
    machine: &mut A,
    threads: &mut [thread::Thread<A>],
    buf: alloc::vec::Vec<u8>,
    path: &[u8],
) -> usize {
    let cpipe = thread::console_pipe();
    let tid = {
        let t = thread::create_thread(threads, machine, None, A::PageTable::default(), true)
            .expect("create Win16 thread");
        t.kernel.fds[0] = thread::FdKind::PipeRead(cpipe);
        t.kernel.fds[1] = thread::FdKind::ConsoleOut;
        t.kernel.fds[2] = thread::FdKind::ConsoleOut;
        t.kernel.tid as usize
    };
    crate::kernel::kpipe::add_reader(cpipe);
    crate::kernel::windows::exec_ne_into(machine, threads, tid, buf, path, b"", None)
        .unwrap_or_else(|e| {
            panic!(
                "Windows NE exec failed ({}): errno {}",
                core::str::from_utf8(path).unwrap_or("?"),
                e
            )
        });
    tid
}

/// Ring-1 kernel event loop. Returns when no threads remain.
///
/// One iteration is the whole kernel, in order: advance the running
/// thread's world (virtual time, console input, delivery), lend it the CPU,
/// canonicalize whatever came back into a `KernelAction`, and ask the
/// scheduler. Every concept lives behind its seam — `ExecutionContext`
/// (the CPU loan), `console` (input routing), `Personality` (the slice
/// hooks + event dispatch), `sched` (policy), `focus` (console ownership,
/// moved together with execution by `switch_focus_and_run` for now). The
/// loop's `display` is `Some` exactly while it is compositing Linux, OSD, or
/// state-only DOS VGA; fullscreen DOS owns the output and leaves it `None`.
fn present_desktop<A: crate::Arch>(
    machine: &mut A,
    bios_workspace: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    threads: &[thread::Thread<A>],
    display: &mut crate::kernel::display::Display,
    windows: &mut crate::kernel::gui::WindowManager,
) {
    // Surface producers establish the presentation edge. OSD changes remain
    // pending and join the next VGA/window publication; they never create an
    // independent compositor clock.
    if !windows.needs_present() {
        return;
    }
    let extent = windows.desktop().extent();
    let (canvas_width, canvas_height) = display.composition_size(
        extent.width as usize,
        extent.height as usize,
    );
    if display.is_host() {
        display.shadow_width = canvas_width;
    }
    windows.sync_osd(
        canvas_width,
        canvas_height,
        display.composition_scale_y(canvas_height),
        display.rgb,
    );
    if !windows.needs_present() {
        return;
    }
    let resolve = |endpoint: crate::kernel::gui::EndpointId,
                   key: crate::kernel::gui::SurfaceKey| {
        threads
            .get(endpoint.0 as usize)?
            .personality
            .surface_buffer(key, display.rgb)
    };
    let shadow = windows
        .compose_processes(resolve, canvas_width, canvas_height, display.rgb)
        .expect("compose process-owned surfaces");
    display.present(machine, bios_workspace, canvas_height, shadow);
}

pub fn event_loop<A: crate::Arch>(
    machine: &mut A,
    bios_workspace: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    threads: &mut [thread::Thread<A>],
    first_tid: usize,
    sb_card: Option<crate::kernel::drivers::sb16::SbCard>,
    mut sink: Option<&mut crate::kernel::sound::Sink>,
    mut display: Option<crate::kernel::display::Display>,
) -> (
    crate::kernel::display::Display,
    Option<crate::kernel::drivers::sb16::SbCard>,
) {
    crate::dbg_println!("event_loop entered, tid={}", first_tid);
    let mut ctx = crate::kernel::exec_ctx::ExecutionContext::seed(threads, first_tid);
    let mut stats = EventStats::new(machine);
    let mut last_osd_refresh_tick = u64::MAX;
    let mut last_world_ns = machine.now();
    // Metal IRQ0 queues Irq::Hw(0); hosted KVM's timer signal returns
    // KernelEvent::Irq. Either is only permission to resample the real clock.
    let mut irq_clock_wakeup = false;
    let mut exiting_display = None;
    let mut audio_clock = crate::kernel::sound::Clock::new();
    // The event loop is the execution engine and sole owner of window policy.
    // A missing display means the initial DOS window holds the fullscreen
    // direct-scanout lease; otherwise the compositor starts on the desktop.
    let initial_window = crate::kernel::gui::WindowManager::primary_window(
        crate::kernel::gui::EndpointId(first_tid as u32),
    );
    let initial_presentation = if display.is_some() {
        crate::kernel::gui::Presentation::Desktop
    } else {
        crate::kernel::gui::Presentation::Fullscreen(initial_window)
    };
    let mut windows = crate::kernel::gui::WindowManager::new(initial_presentation);
    windows.focus(initial_window);
    // The machine's Sound Blaster lives in this frame for the loop's life,
    // beside the display token and for the same reason: it is one piece of
    // hardware with at most one guest owner, and the loop is what outlives
    // every owner. `None` here means a thread currently holds it — or that
    // the kernel mixer owns the card and it never travels at all.
    let mut sb_handoff = threads
        .get_mut(first_tid)
        .and_then(|t| t.personality.adopt_sb(machine, sb_card));

    loop {
        stats.slice_begin(machine);
        stats.iteration(machine);
        let mut events = crate::kernel::irq_dispatch::drain(machine);
        stats.part(machine, 1);
        let tick_wakeup = events
            .iter()
            .any(|event| matches!(event, crate::Irq::Hw(0)));
        events.retain(|event| !matches!(event, crate::Irq::Hw(0)));
        let world_now_ns = if tick_wakeup || irq_clock_wakeup {
            irq_clock_wakeup = false;
            machine.now()
        } else {
            last_world_ns
        };
        let now_tick = world_now_ns / 1_000_000;
        // Keep the F12 window list fresh while it is open,
        // but not on every port/interrupt exit: millisecond resolution is
        // ample for a menu and polling games can cross this loop hundreds of
        // times per tick.
        if crate::kernel::osd::is_open() && now_tick != last_osd_refresh_tick {
            last_osd_refresh_tick = now_tick;
            crate::kernel::osd::refresh_windows(
                threads,
                crate::kernel::focus::focused(),
                !windows.uses_desktop(),
            );
        }
        stats.part(machine, 0);
        // The queue is cheap to drain when empty and carries the IRQ0 wakeup
        // which gates clock sampling, so it cannot itself be clock-gated.
        let elapsed_ns = world_now_ns.saturating_sub(last_world_ns);
        last_world_ns = world_now_ns;

        {
            let thread = ctx.thread(threads);
            debug_assert_eq!(
                display.is_some(),
                thread.personality.uses_compositor(),
                "event-loop display ownership disagrees with personality video state",
            );
            debug_assert!(
                !windows.uses_desktop() || display.is_some(),
                "desktop presentation lost the compositor display",
            );

            // Audio precedes display publication: a synchronous framebuffer
            // write may be slow, but cannot delay the samples due this tick.
            thread.personality.advance_world(
                machine,
                &mut *bios_workspace,
                &ctx.regs,
                world_now_ns,
                elapsed_ns,
                audio_clock.produced_frames(),
            );
            if elapsed_ns != 0 {
                crate::kernel::sound::advance(
                    machine,
                    &mut audio_clock,
                    sink.as_deref_mut(),
                    elapsed_ns,
                    |machine, span| thread.personality.audio_tick(machine, world_now_ns, span),
                );
            }
            if elapsed_ns != 0
                && let Some(display) = display.as_mut()
            {
                let endpoint = crate::kernel::gui::EndpointId(thread.kernel.tid as u32);
                thread.personality.render(
                    machine,
                    &mut *bios_workspace,
                    &ctx.regs,
                    world_now_ns,
                    display,
                    windows.desktop_mut(),
                    endpoint,
                );
            }
        }
        if elapsed_ns != 0
            && let Some(display) = display.as_mut()
        {
            present_desktop(
                machine,
                &mut *bios_workspace,
                threads,
                display,
                &mut windows,
            );
        }
        let thread = ctx.thread(threads);
        stats.part(machine, 2);
        crate::kernel::console::dispatch(
            machine,
            &mut *bios_workspace,
            &mut ctx.regs,
            &mut thread.kernel,
            &mut thread.personality,
            &mut display,
            events,
        );
        if let Some(tid) = crate::kernel::osd::take_window_request() {
            let window = crate::kernel::gui::WindowManager::primary_window(
                crate::kernel::gui::EndpointId(tid as u32),
            );
            windows.select_window(window);
            crate::kernel::osd::finish_presentation_change();
            thread::request_switch_to(tid);
            if tid == ctx.tid {
                apply_current_presentation(
                    machine,
                    &mut *bios_workspace,
                    &mut thread.personality,
                    &mut display,
                    &windows,
                );
            }
        }
        if crate::kernel::osd::take_presentation_request() {
            let window = crate::kernel::gui::WindowManager::primary_window(
                crate::kernel::gui::EndpointId(ctx.tid as u32),
            );
            windows.toggle_presentation(window);
            crate::kernel::osd::finish_presentation_change();
            apply_current_presentation(
                machine,
                &mut *bios_workspace,
                &mut thread.personality,
                &mut display,
                &windows,
            );
        }
        stats.part(machine, 3);
        thread
            .personality
            .after_input(machine, &mut thread.kernel, &mut ctx.regs);
        stats.part(machine, 4);

        // A blocked thread holds the console but not the CPU: wait for input
        // to unblock it (above) or the F12 window picker to move on.
        if thread.kernel.state == thread::ThreadState::Blocked {
            match crate::kernel::sched::focus_request(threads, ctx.tid) {
                Some(next) => switch_focus_and_run(
                    machine,
                    &mut *bios_workspace,
                    threads,
                    &mut ctx,
                    next,
                    &mut exiting_display,
                    &mut sb_handoff,
                    &mut display,
                    &mut windows,
                ),
                None => core::hint::spin_loop(),
            }
            continue;
        }

        // Lend the CPU; canonicalize the outcome into an action.
        stats.pre_run(machine, &ctx.regs);
        let kevent = ctx.run(machine, &thread.personality);
        if matches!(&kevent, crate::KernelEvent::Irq) {
            // Hosted backends express their periodic preemption kick directly
            // as KernelEvent::Irq rather than through the metal IRQ queue.
            irq_clock_wakeup = true;
        }
        stats.post_run(machine, &kevent, &ctx.regs);
        let action = dispatch(machine, &mut *bios_workspace, thread, &mut ctx.regs, kevent);
        stats.after_dispatch(machine);

        // The OSD holds foreground scanout while the personality targets its
        // headless display.
        // Before an owner exits, return that capability so exit_thread can
        // perform its ordinary single release into `exiting_display`.
        if matches!(&action, thread::KernelAction::Exit(_)) && crate::kernel::osd::is_open() {
            crate::kernel::osd::dismiss();
            crate::kernel::console::restore_from_monitor(
                machine,
                &mut *bios_workspace,
                &mut thread.personality,
                &mut display,
            );
        }

        // Ask the scheduler.
        match crate::kernel::sched::verdict(
            machine,
            &mut *bios_workspace,
            threads,
            &mut ctx.regs,
            ctx.tid,
            action,
            &mut exiting_display,
            &mut sb_handoff,
            &mut display,
        ) {
            crate::kernel::sched::Verdict::Stay => {}
            crate::kernel::sched::Verdict::Switch(next) => {
                switch_focus_and_run(
                    machine,
                    &mut *bios_workspace,
                    threads,
                    &mut ctx,
                    next,
                    &mut exiting_display,
                    &mut sb_handoff,
                    &mut display,
                    &mut windows,
                );
            }
            crate::kernel::sched::Verdict::ContinueAs(next) => {
                let old_window = crate::kernel::gui::WindowManager::primary_window(
                    crate::kernel::gui::EndpointId(ctx.tid as u32),
                );
                let new_window = crate::kernel::gui::WindowManager::primary_window(
                    crate::kernel::gui::EndpointId(next as u32),
                );
                windows.inherit_mode(old_window, new_window);
                ctx.continue_as(threads, machine, next);
                windows.select_window(new_window);
                let thread = ctx.thread(threads);
                if !crate::kernel::osd::is_open()
                    && !windows.uses_desktop()
                    && matches!(thread.personality, thread::Personality::Dos(_))
                    && let Some(surface) = display.take()
                {
                    let handoff =
                        crate::kernel::display::DisplayHandoff::from_surface(surface, machine);
                    thread.personality.acquire_display_restore(
                        machine,
                        &mut *bios_workspace,
                        handoff,
                    );
                }
            }
            crate::kernel::sched::Verdict::AllDead => {
                // The loop's contract: no thread resources survive it —
                // callers never inherit zombies.
                thread::reap_all_zombies(threads, machine);
                // Every owner is gone, so both capabilities are back in this
                // frame — hand them to whoever runs the next program.
                return (
                    match display.take() {
                        Some(display) => display,
                        None => exiting_display
                            .take()
                            .expect("dead display owner lost token")
                            .into_surface(machine, &mut *bios_workspace),
                    },
                    sb_handoff.take(),
                );
            }
        }
    }
}

/// Canonicalize a kernel event into the action the scheduler decides on.
/// Page faults are decided here — an unhandled user fault is a SEGV exit,
/// and `signal_thread` wants the whole `Thread` for its diagnostics;
/// everything else is the personality's call.
fn dispatch<A: crate::Arch>(
    machine: &mut A,
    bios_display: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    thread: &mut thread::Thread<A>,
    regs: &mut Regs,
    kevent: crate::KernelEvent,
) -> thread::KernelAction {
    // The F12 monitor's Kill acts on the focused thread — which, under today's
    // focus/execution coupling, is exactly this one. Turn it into an ordinary
    // Exit so `exit_thread` does all teardown and hands focus back to the
    // parent, the same path SEGV takes below.
    if crate::kernel::osd::take_kill_request() {
        // DOS exit type decides the VGA return contract: normal termination
        // transfers the live adapter, while type 02h restores the parent's
        // pre-child recovery image. Preserve Unix status for Linux, but encode
        // an OSD kill as DOS critical termination.
        let code = match thread.personality {
            thread::Personality::Dos(_) => 0x0200,
            thread::Personality::Linux(_)
            | thread::Personality::Os2(_)
            | thread::Personality::Windows(_) => -9,
        };
        return thread::KernelAction::Exit(code);
    }
    if let crate::KernelEvent::PageFault { addr } = kevent {
        // A VGA planar-trap access (A0000 unmapped while unchained graphics
        // needs the write/read planar logic) is decoded + emulated here, not a
        // SEGV. Same path on both backends — both deliver this PageFault.
        if thread.personality.try_vga_fault(machine, regs, addr) {
            return thread::KernelAction::Done;
        }
        crate::println!(
            "  fault rip={:#x} addr={:#x} err={:#x}",
            regs.frame.rip,
            addr,
            regs.err_code
        );
        crate::println!(
            "  rax={:#x} rbx={:#x} rcx={:#x} rdx={:#x} rsi={:#x} rdi={:#x} rbp={:#x} rsp={:#x}",
            regs.rax,
            regs.rbx,
            regs.rcx,
            regs.rdx,
            regs.rsi,
            regs.rdi,
            regs.rbp,
            regs.frame.rsp
        );
        crate::println!(
            "  r8={:#x} r9={:#x} r10={:#x} r11={:#x} r12={:#x} r13={:#x} r14={:#x} r15={:#x}",
            regs.r8,
            regs.r9,
            regs.r10,
            regs.r11,
            regs.r12,
            regs.r13,
            regs.r14,
            regs.r15
        );
        let code = match thread.personality {
            thread::Personality::Dos(_) => 0x020E, // type 02h, vector 0Eh (#PF)
            thread::Personality::Linux(_)
            | thread::Personality::Os2(_)
            | thread::Personality::Windows(_) => -11,
        };
        thread::signal_thread(thread, addr as usize);
        return thread::KernelAction::Exit(code);
    }
    thread
        .personality
        .handle_event(machine, bios_display, &mut thread.kernel, regs, kevent)
}

/// Switch console focus and execution together — today's coupling, in one
/// named place. The event loop runs the focused thread, so every execution
/// switch is also a focus handoff (release: out-focus screen snapshot with
/// the old context live; acquire: in-focus repaint with the new context
/// live). When the scheduler decouples them, this helper is what splits.
///
/// Zombies skip the release because `exit_thread` already released the
/// display before `arch_user_clean` unmapped 0xA0000. On normal DOS return,
/// the incoming parent is marked to adopt that still-live adapter; on an
/// error or ordinary background switch it restores its detached snapshot.
#[allow(clippy::too_many_arguments)]
fn switch_focus_and_run<A: crate::Arch>(
    machine: &mut A,
    bios_workspace: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    threads: &mut [thread::Thread<A>],
    ctx: &mut crate::kernel::exec_ctx::ExecutionContext<A>,
    new_tid: usize,
    exiting_display: &mut Option<crate::kernel::display::ExitDisplay>,
    sb_handoff: &mut Option<crate::kernel::drivers::sb16::SbCard>,
    display: &mut Option<crate::kernel::display::Display>,
    windows: &mut crate::kernel::gui::WindowManager,
) {
    if new_tid == ctx.tid {
        let focused = crate::kernel::focus::focused();
        if focused == new_tid {
            return;
        }
        // Focus-only handoff: move the output without changing address space.
        let owner_zombie = thread::get_thread(threads, focused)
            .is_none_or(|t| t.kernel.state == thread::ThreadState::Zombie);
        if owner_zombie {
            return; // exit transaction owns the display; nothing to move here
        }
        let owner = thread::get_thread(threads, focused).expect("focus handoff: owner");
        let handoff = match display.take() {
            Some(display) => crate::kernel::display::DisplayHandoff::from_surface(display, machine),
            None => owner.personality.release_display(machine, bios_workspace),
        };
        let card = owner.personality.release_sb(machine);
        if card.is_some() {
            assert!(sb_handoff.is_none(), "stale SB handoff");
            *sb_handoff = card;
        }
        let new = thread::get_thread(threads, new_tid).expect("focus handoff: new owner");
        select_window_for_tid(windows, new_tid);
        if crate::kernel::osd::is_open()
            || windows.uses_desktop()
            || matches!(
                new.personality,
                thread::Personality::Linux(_)
                    | thread::Personality::Os2(_)
                    | thread::Personality::Windows(_)
            )
        {
            *display = Some(handoff.into_surface(machine, bios_workspace));
            new.personality.repaint_osd();
        } else {
            new.personality
                .acquire_display_restore(machine, bios_workspace, handoff);
        }
        crate::kernel::focus::adopt(new_tid);
        *sb_handoff = new.personality.adopt_sb(machine, sb_handoff.take());
        return;
    }
    // Normal DOS return has already named the parent as focus, but the child
    // VGA remains in the explicit exit transaction until the parent space is
    // active.
    if crate::kernel::focus::focused() == new_tid {
        let old = thread::get_thread(threads, ctx.tid).expect("switch: invalid old thread");
        if let Some(card) = old.personality.release_sb(machine) {
            assert!(sb_handoff.is_none(), "stale SB handoff");
            *sb_handoff = Some(card);
        }
        let transfer = exiting_display.take();
        ctx.switch_to(threads, machine, new_tid);
        let new = thread::get_thread(threads, new_tid).expect("switch: invalid new thread");
        select_window_for_tid(windows, new_tid);
        match transfer {
            Some(crate::kernel::display::ExitDisplay::DosReplace(returned)) => {
                let thread::Personality::Dos(dos) = &mut new.personality else {
                    unreachable!("DOS VGA returned to non-DOS parent")
                };
                dos.pc.vga.acquire_parent_replace(machine, returned);
            }
            Some(crate::kernel::display::ExitDisplay::Restore(handoff)) => {
                if crate::kernel::osd::is_open()
                    || windows.uses_desktop()
                    || matches!(
                        new.personality,
                        thread::Personality::Linux(_)
                            | thread::Personality::Os2(_)
                            | thread::Personality::Windows(_)
                    )
                {
                    *display = Some(handoff.into_surface(machine, bios_workspace));
                } else {
                    new.personality
                        .acquire_display_restore(machine, bios_workspace, handoff);
                }
            }
            None => {}
        }
        *sb_handoff = new.personality.adopt_sb(machine, sb_handoff.take());
        return;
    }
    let old_is_zombie = thread::get_thread(threads, ctx.tid)
        .expect("switch: invalid old thread")
        .kernel
        .state
        == thread::ThreadState::Zombie;
    let transfer = if !old_is_zombie {
        assert!(exiting_display.is_none(), "stale exiting display");
        let old = thread::get_thread(threads, ctx.tid).expect("switch: invalid old thread");
        let handoff = match display.take() {
            Some(display) => crate::kernel::display::DisplayHandoff::from_surface(display, machine),
            None => old.personality.release_display(machine, bios_workspace),
        };
        let card = old.personality.release_sb(machine);
        if card.is_some() {
            assert!(sb_handoff.is_none(), "stale SB handoff");
            *sb_handoff = card;
        }
        Some(crate::kernel::display::ExitDisplay::Restore(handoff))
    } else {
        exiting_display.take()
    };
    ctx.switch_to(threads, machine, new_tid);
    let new = thread::get_thread(threads, new_tid).expect("switch: invalid new thread");
    select_window_for_tid(windows, new_tid);
    match transfer {
        Some(crate::kernel::display::ExitDisplay::Restore(handoff)) => {
            if crate::kernel::osd::is_open()
                || windows.uses_desktop()
                || matches!(
                    new.personality,
                    thread::Personality::Linux(_)
                        | thread::Personality::Os2(_)
                        | thread::Personality::Windows(_)
                )
            {
                *display = Some(handoff.into_surface(machine, bios_workspace));
                new.personality.repaint_osd();
            } else {
                new.personality
                    .acquire_display_restore(machine, bios_workspace, handoff);
            }
        }
        Some(crate::kernel::display::ExitDisplay::DosReplace(returned)) => {
            let thread::Personality::Dos(dos) = &mut new.personality else {
                unreachable!("DOS VGA returned to non-DOS parent")
            };
            dos.pc.vga.acquire_parent_replace(machine, returned);
        }
        None => assert!(display.is_some(), "zombie lost display"),
    }
    if !crate::kernel::osd::is_open()
        && !windows.uses_desktop()
        && matches!(new.personality, thread::Personality::Dos(_))
        && let Some(surface) = display.take()
    {
        let handoff = crate::kernel::display::DisplayHandoff::from_surface(surface, machine);
        new.personality
            .acquire_display_restore(machine, bios_workspace, handoff);
    }
    crate::kernel::focus::adopt(new_tid);
    *sb_handoff = new.personality.adopt_sb(machine, sb_handoff.take());
}

fn select_window_for_tid(windows: &mut crate::kernel::gui::WindowManager, tid: usize) {
    let window = crate::kernel::gui::WindowManager::primary_window(
        crate::kernel::gui::EndpointId(tid as u32),
    );
    windows.select_window(window);
}

fn apply_current_presentation<A: crate::Arch>(
    machine: &mut A,
    bios_workspace: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    personality: &mut thread::Personality<A>,
    display: &mut Option<crate::kernel::display::Display>,
    windows: &crate::kernel::gui::WindowManager,
) {
    if windows.uses_desktop() {
        if display.is_none() {
            let handoff = personality.release_display(machine, bios_workspace);
            *display = Some(handoff.into_surface(machine, bios_workspace));
        }
    } else if matches!(personality, thread::Personality::Dos(_))
        && let Some(surface) = display.take()
    {
        let handoff = crate::kernel::display::DisplayHandoff::from_surface(surface, machine);
        personality.acquire_display_restore(machine, bios_workspace, handoff);
    }
}

/// Fork the current process and exec a binary (DOS .COM/.EXE or ELF) in the child.
/// Blocks parent, returns child tid on success, None on error (caller stays on parent).
#[allow(clippy::too_many_arguments)]
pub(crate) fn handle_fork_exec<A: crate::Arch>(
    machine: &mut A,
    bios_workspace: &mut crate::kernel::bios_display::BiosDisplayWorkspace<A>,
    threads: &mut [thread::Thread<A>],
    vcpu: &mut Regs,
    parent_tid: usize,
    path: &[u8],
    cmdtail: &[u8],
    personality_name: Option<thread::PersonalityName>,
    viopl: u8,
    on_error: fn(&mut crate::Regs, i32),
    on_success: fn(&mut crate::Regs, i32),
    sb_handoff: &mut Option<crate::kernel::drivers::sb16::SbCard>,
    event_display: &mut Option<crate::kernel::display::Display>,
) -> Option<usize> {
    use crate::kernel::exec;

    let parent = thread::get_thread(threads, parent_tid).expect("fork_exec: invalid parent");
    let parent_was_focused = crate::kernel::focus::focused() == parent_tid;

    // Snapshot the parent's cwd and (DOS-only) env block while we're still in
    // the parent's address space. The COW fork + arch_user_clean inside
    // exec_dos_into tears the parent's pages out from under us, so anything
    // the child needs from parent memory must be copied to the kernel heap.
    //
    // cwd lives in the personality state (`DfsState` for DOS, `LinuxState`
    // for Linux); convert to common VFS-form (lowercase, forward-slash) for
    // child init.
    let mut parent_cwd_buf = [0u8; 66];
    let parent_cwd_len: usize;
    let parent_env_snapshot: Option<alloc::vec::Vec<u8>>;
    let parent_is_dos: bool;
    let parent_fds = parent.kernel.fds;
    match &parent.personality {
        thread::Personality::Dos(dos) => {
            parent_is_dos = true;
            // Drive-qualified ("D:", "C:BOOT"): the child inherits the
            // parent's CURRENT DRIVE, not just the path within it — a
            // program launched from D:\ must resolve relative opens
            // against D:\ (init_from_vfs decodes the "X:" prefix).
            let dos_cwd = dos.dfs.get_cwd();
            parent_cwd_buf[0] = b'A' + dos.dfs.current_drive_number();
            parent_cwd_buf[1] = b':';
            let n = dos_cwd.len().min(parent_cwd_buf.len() - 2);
            for i in 0..n {
                parent_cwd_buf[2 + i] = if dos_cwd[i] == b'\\' {
                    b'/'
                } else {
                    dos_cwd[i]
                };
            }
            parent_cwd_len = 2 + n;

            parent_env_snapshot = Some(crate::kernel::dos::snapshot_parent_env(machine, vcpu, dos));
        }
        thread::Personality::Linux(lin) => {
            parent_is_dos = false;
            let cwd = lin.cwd_str();
            parent_cwd_buf[..cwd.len()].copy_from_slice(cwd);
            parent_cwd_len = cwd.len();
            parent_env_snapshot = None;
        }
        thread::Personality::Os2(os2) => {
            parent_is_dos = false;
            let cwd = os2.cwd_str();
            parent_cwd_buf[..cwd.len()].copy_from_slice(cwd);
            parent_cwd_len = cwd.len();
            parent_env_snapshot = None;
        }
        thread::Personality::Windows(windows) => {
            parent_is_dos = false;
            let cwd = windows.cwd_str();
            parent_cwd_buf[..cwd.len()].copy_from_slice(cwd);
            parent_cwd_len = cwd.len();
            parent_env_snapshot = None;
        }
    }

    // `path` is in the launcher's namespace. For a DOS launcher it's a DOS path
    // — map it to VFS (DOS layer's translator) only for the read; the DOS form
    // is kept as-is for the program name. Otherwise it's already VFS.
    let read_path: alloc::vec::Vec<u8> = match personality_name {
        Some(thread::PersonalityName::Dos) => match crate::kernel::dos::dos_abs_to_vfs(path) {
            Some(v) => v,
            None => {
                on_error(vcpu, 2);
                return None;
            }
        },
        _ => path.to_vec(),
    };
    let buf = match exec::load_file_resolved(&read_path) {
        Ok(b) => b,
        Err(_) => {
            on_error(vcpu, 2);
            return None;
        }
    };

    let format = exec::detect_format(&buf, path);
    crate::dbg_println!(
        "handle_fork_exec: {:?} size={} format={} free_pages={}",
        core::str::from_utf8(path),
        buf.len(),
        match format {
            exec::BinaryFormat::Elf => "elf",
            exec::BinaryFormat::Lx => "lx",
            exec::BinaryFormat::Pe => "pe",
            exec::BinaryFormat::Ne => "ne",
            exec::BinaryFormat::MzExe => "exe",
            exec::BinaryFormat::Com => "com",
        },
        machine.free_page_count()
    );

    // Release while the parent's address space is live. The returned token is
    // the only physical display ownership during construction; the parent's
    // record is now a complete emulated recovery image.
    let fork_display = parent_was_focused.then(|| match event_display.take() {
        Some(display) => crate::kernel::display::DisplayHandoff::from_surface(display, machine),
        None => {
            let parent = thread::get_thread(threads, parent_tid).unwrap();
            parent.personality.release_display(machine, bios_workspace)
        }
    });
    let mut fork_sb = if parent_was_focused {
        sb_handoff.take()
    } else {
        None
    };
    if parent_was_focused
        && let Some(card) = thread::get_thread(threads, parent_tid)
            .unwrap()
            .personality
            .release_sb(machine)
    {
        assert!(fork_sb.is_none(), "two Sound Blaster owners at fork");
        fork_sb = Some(card);
    }

    let exec_vga = match format {
        exec::BinaryFormat::Elf | exec::BinaryFormat::Lx | exec::BinaryFormat::Ne
            | exec::BinaryFormat::Pe => {
            exec::ExecVga::None
        }
        _ if parent_is_dos => {
            let parent = thread::get_thread(threads, parent_tid).unwrap();
            let thread::Personality::Dos(parent) = &mut parent.personality else {
                unreachable!("parent_is_dos without DOS personality")
            };
            let vga = parent
                .pc
                .vga
                .clone_detached_for_child(machine)
                .unwrap_or_else(|| {
                    crate::kernel::bios_display::DosVideo::Vga(
                        crate::kernel::bios_display::EmulatedVga::initial_mode3(),
                    )
                });
            exec::ExecVga::Dos(vga)
        }
        _ => exec::ExecVga::Dos(crate::kernel::bios_display::DosVideo::Vga(
            crate::kernel::bios_display::EmulatedVga::initial_mode3(),
        )),
    };

    // Reserve a child record, then COW the live address space into the parent
    // continuation. The unchanged live address space is henceforth the child.
    let child_tid = {
        let child = match thread::reserve_live_child(threads, machine, parent_tid) {
            Some(t) => t,
            None => {
                if let Some(display) = fork_display {
                    let parent = thread::get_thread(threads, parent_tid).unwrap();
                    if crate::kernel::osd::is_open()
                        || matches!(
                            parent.personality,
                            thread::Personality::Linux(_)
                                | thread::Personality::Os2(_)
                                | thread::Personality::Windows(_)
                        )
                    {
                        *event_display = Some(display.into_surface(machine, bios_workspace));
                    } else {
                        parent.personality.acquire_display_restore(
                            machine,
                            bios_workspace,
                            display,
                        );
                    }
                }
                if parent_was_focused {
                    *sb_handoff = thread::get_thread(threads, parent_tid)
                        .unwrap()
                        .personality
                        .adopt_sb(machine, fork_sb);
                }
                on_error(vcpu, 8);
                return None;
            }
        };
        child.kernel.tid as usize
    };
    {
        let parent = thread::get_thread(threads, parent_tid).unwrap();
        machine.user_fork(&mut parent.kernel.vcpu.space);
    }

    // ELF needs user pages freed before loading; DOS handles its own address space
    if matches!(
        format,
        exec::BinaryFormat::Elf | exec::BinaryFormat::Lx | exec::BinaryFormat::Ne
            | exec::BinaryFormat::Pe
    ) {
        crate::dbg_println!("  fork done, loading protected-mode image...");
        machine.free_user_pages();
    }

    let args = alloc::vec![path.to_vec()];
    let cmdtail = cmdtail.to_vec();
    let env = parent_env_snapshot.unwrap_or_default();
    let cwd = parent_cwd_buf[..parent_cwd_len].to_vec();
    if exec::init_thread(
        machine,
        threads,
        child_tid,
        buf,
        path,
        args,
        cmdtail,
        env,
        cwd,
        personality_name,
        viopl,
        exec_vga,
    )
    .is_err()
    {
        // Tear down the half-built live child before returning to the parked
        // parent, then restore the parent's saved display image.
        {
            let child = thread::get_thread(threads, child_tid).unwrap();
            if let thread::Personality::Dos(dos) = &mut child.personality {
                dos.on_exit(machine, &mut child.kernel.vcpu, false);
            }
            child.kernel.close_all_fds();
        }
        machine.free_user_pages();
        let parent_space = {
            let parent = thread::get_thread(threads, parent_tid).unwrap();
            core::mem::take(&mut parent.kernel.vcpu.space)
        };
        let discarded_child =
            machine.activate(parent_space, core::ptr::null_mut(), core::ptr::null_mut());
        {
            let child = thread::get_thread(threads, child_tid).unwrap();
            child.kernel.vcpu.space = discarded_child;
            machine.destroy_space(&mut child.kernel.vcpu.space);
            child.personality = thread::Personality::Linux(crate::kernel::linux::LinuxState::new());
            child.kernel.state = thread::ThreadState::Unused;
        }
        let parent = thread::get_thread(threads, parent_tid).unwrap();
        parent.personality.on_resume(machine);
        if let Some(display) = fork_display {
            if crate::kernel::osd::is_open()
                || matches!(
                    parent.personality,
                    thread::Personality::Linux(_)
                        | thread::Personality::Os2(_)
                        | thread::Personality::Windows(_)
                )
            {
                *event_display = Some(display.into_surface(machine, bios_workspace));
            } else {
                parent
                    .personality
                    .acquire_display_restore(machine, bios_workspace, display);
            }
        }
        if parent_was_focused {
            *sb_handoff = parent.personality.adopt_sb(machine, fork_sb);
        }
        on_error(vcpu, 11);
        return None;
    }

    // Hardware/current surface wins on successful EXEC. Bind it to the live
    // child without replaying the parent's recovery image.
    if let Some(display) = fork_display {
        let child = thread::get_thread(threads, child_tid).unwrap();
        if crate::kernel::osd::is_open()
            || matches!(
                child.personality,
                thread::Personality::Linux(_)
                    | thread::Personality::Os2(_)
                    | thread::Personality::Windows(_)
            )
        {
            *event_display = Some(display.into_surface(machine, bios_workspace));
        } else {
            child
                .personality
                .acquire_display_replace(machine, bios_workspace, display);
        }
    }
    if parent_was_focused {
        *sb_handoff = thread::get_thread(threads, child_tid)
            .unwrap()
            .personality
            .adopt_sb(machine, fork_sb);
    }

    let child = thread::get_thread(threads, child_tid).unwrap();

    match &mut child.personality {
        thread::Personality::Linux(lin) => {
            // Inherit cwd from parent. (DOS path seeds DfsState inside
            // init_process_thread_vm86; Linux child stores cwd in LinuxState.)
            lin.cwd[..parent_cwd_len].copy_from_slice(&parent_cwd_buf[..parent_cwd_len]);
            lin.cwd_len = parent_cwd_len;
            let cpipe = thread::console_pipe();
            child.kernel.fds[0] = thread::FdKind::PipeRead(cpipe);
            child.kernel.fds[1] = thread::FdKind::ConsoleOut;
            child.kernel.fds[2] = thread::FdKind::ConsoleOut;
            crate::kernel::kpipe::add_reader(cpipe);
        }
        thread::Personality::Os2(os2) => {
            let n = parent_cwd_len.min(os2.cwd.len());
            os2.cwd[..n].copy_from_slice(&parent_cwd_buf[..n]);
            os2.cwd_len = n;
            let cpipe = thread::console_pipe();
            child.kernel.fds[0] = thread::FdKind::PipeRead(cpipe);
            child.kernel.fds[1] = thread::FdKind::ConsoleOut;
            child.kernel.fds[2] = thread::FdKind::ConsoleOut;
            crate::kernel::kpipe::add_reader(cpipe);
        }
        thread::Personality::Windows(windows) => {
            let n = parent_cwd_len.min(windows.cwd.len());
            windows.cwd[..n].copy_from_slice(&parent_cwd_buf[..n]);
            windows.cwd_len = n;
            let cpipe = thread::console_pipe();
            child.kernel.fds[0] = thread::FdKind::PipeRead(cpipe);
            child.kernel.fds[1] = thread::FdKind::ConsoleOut;
            child.kernel.fds[2] = thread::FdKind::ConsoleOut;
            crate::kernel::kpipe::add_reader(cpipe);
        }
        thread::Personality::Dos(_) => {
            // DOS EXEC semantics: the child inherits the parent's JFT —
            // including handles the parent just redirected. Borland's IDE
            // depends on this: it forces the transfer program's stdout into
            // its message pipe (AH=45h/46h), EXECs, and restores after.
            // Exit closes them again (close_all_fds), so the refcounts pair.
            if parent_is_dos {
                for (slot, inherited) in child.kernel.fds.iter_mut().zip(parent_fds.iter()) {
                    *slot = match *inherited {
                        k @ thread::FdKind::Vfs(h) => {
                            crate::kernel::vfs::add_vfs_ref(h);
                            k
                        }
                        k @ thread::FdKind::ConsoleOut => k,
                        thread::FdKind::PipeRead(p) => {
                            crate::kernel::kpipe::add_reader(p);
                            thread::FdKind::PipeRead(p)
                        }
                        thread::FdKind::PipeWrite(p) => {
                            crate::kernel::kpipe::add_writer(p);
                            thread::FdKind::PipeWrite(p)
                        }
                        // Sockets/dirs have no DOS-handle meaning; don't
                        // clone what the child can't address.
                        _ => thread::FdKind::None,
                    };
                }
            }
            machine.outb(0x3D4, 0x0E);
            let cursor_hi = machine.inb(0x3D5) as u16;
            machine.outb(0x3D4, 0x0F);
            let cursor_lo = machine.inb(0x3D5) as u16;
            let cursor_off = (cursor_hi << 8) | cursor_lo;
            let col = (cursor_off % 80) as u8;
            let row = (cursor_off / 80) as u8;
            // BDA 0040:0050 — the page-0 cursor position the child's BIOS
            // sees. Must go through the Vcpu guest accessor: a guest address
            // is a host address only on metal's low-mem identity window — on
            // the interp backend treating the guest address as a host pointer
            // hits the host null page (SEGV'd on DN→PRINCE.EXE, the first
            // task-spawn EXEC on interp).
            crate::kernel::dos::Bda::set_page0_cursor(machine, col, row);
        }
    }

    if parent_was_focused {
        crate::kernel::focus::adopt(child_tid);
    }

    // Switch focus to child. Parent stays Ready; it'll poll SYNTH_WAITPID
    // when focus returns to it. No kernel-side blocking — the focused thread
    // runs continuously, so polling is just a status query.
    crate::dbg_println!(
        "  child tid={}, parent tid={} continues without blocking",
        child_tid,
        parent_tid
    );
    on_success(vcpu, child_tid as i32);
    {
        let (parent, child) = thread::get_two_threads(threads, parent_tid, child_tid);
        parent.kernel.vcpu.regs = *vcpu;
        let mut clean_child_fx = machine.clean_fx_template();
        machine.switch_fx(&mut clean_child_fx);
        parent.kernel.fx_state = clean_child_fx;
        *vcpu = child.kernel.vcpu.regs;
    }
    Some(child_tid)
}

/// F12 handler: dump the user thread state that was interrupted when F12 was
/// pressed. `regs` is always a user frame — the kernel event loop is never
/// interrupted by hardware IRQs.
/// - VM86: print guest CS:IP, common registers, BIOS timer, code bytes, and
///   the 80x25 VGA text buffer (for diagnosing hung DOS programs).
/// - PM: Rust stack trace via frame-pointer walking through user symbols.
///
/// `dos` (when present) adds virtual PIC/PIT state — useful for diagnosing
/// stuck IRQ delivery (e.g. an in-service bit never cleared by a missed EOI).
pub fn arch_dump_exception<A: crate::Arch>(
    machine: &mut A,
    dos: &thread::DosState<A>,
    regs: &Regs,
) {
    dump_interrupted_thread(machine, regs, Some(dos));
}

pub(crate) fn dump_interrupted_thread<A: crate::Arch>(
    machine: &mut A,
    regs: &Regs,
    dos: Option<&thread::DosState<A>>,
) {
    let vm86 = regs.flags32() & (1 << 17) != 0;
    if vm86 {
        // The guest's interrupt flag is VIF (bit 19); canonical bit 9 is
        // pinned to 1 and carries nothing.
        let vif = regs.flags32() & (1 << 19) != 0;
        let lin = (regs.cs32() << 4) + regs.ip32();
        // Guest reads via arch::mem() (identity on metal, mmap offset on the
        // interpreter) — raw `lin as *const u8` would fault on the interp.
        let mut b = [0u8; 8];
        machine.copy_from(lin as usize, &mut b);
        let ticks = crate::kernel::dos::Bda::tick_count(machine);
        crate::dbg_println!(
            "[DBG] VM86 {:04X}:{:04X} AX={:04X} BX={:04X} CX={:04X} DX={:04X} DS={:04X} SS:SP={:04X}:{:04X} flags={:04X} VIF={} ticks={} code={:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            regs.code_seg(),
            regs.ip32(),
            regs.rax as u16,
            regs.rbx as u16,
            regs.rcx as u16,
            regs.rdx as u16,
            regs.ds as u16,
            regs.stack_seg(),
            regs.sp32(),
            regs.flags32() as u16,
            vif as u8,
            ticks,
            b[0],
            b[1],
            b[2],
            b[3],
            b[4],
            b[5],
            b[6],
            b[7]
        );
        if let Some(d) = dos {
            dump_virtual_hw(d);
        }
        // Dump VGA hardware register state (which one differs vs working
        // is the first thing to check when buffer paints but screen is
        // black — most often SEQ[1] bit 5 = screen-off, GC[6] framebuffer
        // mapping, or AC mode register text-vs-graphics).
        {
            use crate::kernel::portio::{inb, outb};
            let _ = inb(0x3DA);
            let misc = inb(0x3CC);
            let mut seq = [0u8; 5];
            for i in 0..5u8 {
                outb(0x3C4, i);
                seq[i as usize] = inb(0x3C5);
            }
            let mut crtc = [0u8; 25];
            for i in 0..25u8 {
                outb(0x3D4, i);
                crtc[i as usize] = inb(0x3D5);
            }
            let mut gc = [0u8; 9];
            for i in 0..9u8 {
                outb(0x3CE, i);
                gc[i as usize] = inb(0x3CF);
            }
            let _ = inb(0x3DA);
            let mut ac = [0u8; 21];
            for i in 0..21u8 {
                let _ = inb(0x3DA);
                outb(0x3C0, i | 0x20);
                ac[i as usize] = inb(0x3C1);
            }
            let _ = inb(0x3DA);
            outb(0x3C0, 0x20); // re-enable display by setting PAS
            crate::dbg_println!(
                "[VGA HW] misc={:02X} seq=[{:02X} {:02X} {:02X} {:02X} {:02X}]",
                misc,
                seq[0],
                seq[1],
                seq[2],
                seq[3],
                seq[4]
            );
            crate::dbg_println!(
                "[VGA HW] gc=[{:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}]",
                gc[0],
                gc[1],
                gc[2],
                gc[3],
                gc[4],
                gc[5],
                gc[6],
                gc[7],
                gc[8]
            );
            crate::dbg_println!(
                "[VGA HW] ac[10..14]={:02X} {:02X} {:02X} {:02X}  crtc[0C..0F]={:02X} {:02X} {:02X} {:02X}",
                ac[0x10],
                ac[0x11],
                ac[0x12],
                ac[0x13],
                crtc[0x0C],
                crtc[0x0D],
                crtc[0x0E],
                crtc[0x0F]
            );
        }
        // Dump VGA text buffer (80x25, char+attr interleaved at 0xB8000).
        // Through arch::mem() so it works on both backends — `0xB8000` is a
        // guest address, identity-mapped on metal but an mmap offset on the
        // interpreter (a raw `0xB8000 as *const u8` would fault there).
        let mut vga = [0u8; 4000];
        machine.copy_from(0xB8000, &mut vga);
        for row in 0..25 {
            let mut line = [b'.'; 80];
            for col in 0..80 {
                let ch = vga[(row * 80 + col) * 2];
                line[col] = if (0x20..0x7F).contains(&ch) { ch } else { b'.' };
            }
            crate::dbg_println!(
                "[VGA {:02}] {}",
                row,
                core::str::from_utf8(&line).unwrap_or("???")
            );
        }
    } else {
        let fl = regs.flags32();
        crate::dbg_println!(
            "[DBG] PM CS:EIP={:04x}:{:#010x} SS:ESP={:04x}:{:#010x} EFLAGS={:#010x} VIF={} vIOPL={}",
            regs.code_seg(),
            regs.ip32(),
            regs.stack_seg(),
            regs.sp32(),
            fl,
            (fl >> 19) & 1,
            (fl >> 12) & 3
        );
        crate::dbg_println!(
            "[DBG] AX={:08x} BX={:08x} CX={:08x} DX={:08x} SI={:08x} DI={:08x} BP={:08x}",
            regs.rax as u32,
            regs.rbx as u32,
            regs.rcx as u32,
            regs.rdx as u32,
            regs.rsi as u32,
            regs.rdi as u32,
            regs.rbp as u32
        );
        crate::dbg_println!(
            "[DBG] DS={:04x} ES={:04x} FS={:04x} GS={:04x}",
            regs.ds as u16,
            regs.es as u16,
            regs.fs as u16,
            regs.gs as u16
        );
        if let Some(d) = dos {
            crate::kernel::dos::dump_dpmi_state(machine, d, regs);
            dump_virtual_hw(d);
        }
        crate::kernel::stacktrace::stack_trace_regs(regs);
    }
}

/// Print virtual PIC/PIT state — the actual IRQ-delivery gating lives here,
/// so hangs that look like "timer stopped" usually show up as a stuck in-
/// service bit (a higher-priority pending line is blocked by it) or a
/// requested-but-masked line.
fn dump_virtual_hw<A: crate::Arch>(dos: &thread::DosState<A>) {
    let (mirr, misr, mimr, sirr, sisr, simr) = dos.pc.vpic.debug_state();
    crate::dbg_println!(
        "[DBG] vpic master irr={:#04x} isr={:#04x} imr={:#04x}  slave irr={:#04x} isr={:#04x} imr={:#04x}",
        mirr,
        misr,
        mimr,
        sirr,
        sisr,
        simr
    );

    let (en, mode, reload, now, next) = dos.pc.vpit.debug_state();
    let delta = (next as i64).wrapping_sub(now as i64);
    crate::dbg_println!(
        "[DBG] vpit ch0 en={} mode={} reload={} now={} next={} (next-now={})",
        en,
        mode,
        reload,
        now,
        next,
        delta
    );

    crate::kernel::dos::dump_if_ring();
    crate::kernel::dos::dump_gus_ring();
}

/// Event-loop diagnostics: per-event-type counts, user/kernel cycle split,
/// the periodic [prof] dump, and the free-page low-water sampling. Keeps
/// the loop body logic, not bookkeeping.
/// Event-loop world-advance costs, billed from `thread.rs`: timer/device work,
/// display, audio, and tick count. Diagnostic only — read by the profile dump.
static mut SLICE_PARTS: [u64; 5] = [0; 5];

/// Count of actual frame presentations (past the frame_due gate), so the
/// tick+display total can be divided by the right denominator.
static mut PRESENTS: u64 = 0;

/// display_tick's internals: scanout cycles, render-pass count (one complete
/// shadow or one whole window-sink frame per bill), VGA render cycles, final
/// framebuffer/window publication cycles, and destination pixels written.
static mut DISP_PARTS: [u64; 5] = [0; 5];
static mut DISP_MODE: vga::VgaMode = vga::VgaMode::Text {
    cols: 80,
    rows: 25,
    cell_w: 9,
    cell_h: 16,
};

pub fn bill_display(
    mode: vga::VgaMode,
    scanout: u64,
    renders: u64,
    render: u64,
    present: u64,
    px: usize,
) {
    unsafe {
        core::ptr::write_volatile(&raw mut DISP_MODE, mode);
        let p = &raw mut DISP_PARTS;
        (*p)[0] = (*p)[0].wrapping_add(scanout);
        (*p)[1] = (*p)[1].wrapping_add(renders);
        (*p)[2] = (*p)[2].wrapping_add(render);
        (*p)[3] = (*p)[3].wrapping_add(present);
        (*p)[4] = (*p)[4].wrapping_add(px as u64);
    }
}

/// Audio-pump diagnostics: device maintenance, pacing setup, source mixing and
/// sink output, guest clocks/IRQ delivery, and canonical frames generated.
static mut AUDIO_PARTS: [u64; 5] = [0; 5];
/// `audio_service` split: Sound Blaster, GUS, MPU-401. This runs outside the
/// sample pump and used to disappear into `world-other` on zero-tick exits.
static mut AUDIO_SERVICE_PARTS: [u64; 3] = [0; 3];
/// Mixer source split: Sound Blaster, GUS, MPU/GM synth, PC speaker.
static mut AUDIO_SOURCE_PARTS: [u64; 4] = [0; 4];

pub fn bill_audio(devices: u64, setup: u64, pump: u64, clocks: u64, frames: u64) {
    unsafe {
        let p = &raw mut AUDIO_PARTS;
        (*p)[0] = (*p)[0].wrapping_add(devices);
        (*p)[1] = (*p)[1].wrapping_add(setup);
        (*p)[2] = (*p)[2].wrapping_add(pump);
        (*p)[3] = (*p)[3].wrapping_add(clocks);
        (*p)[4] = (*p)[4].wrapping_add(frames);
    }
}

pub fn bill_audio_service(sb: u64, gus: u64, mpu: u64) {
    unsafe {
        let p = &raw mut AUDIO_SERVICE_PARTS;
        (*p)[0] = (*p)[0].wrapping_add(sb);
        (*p)[1] = (*p)[1].wrapping_add(gus);
        (*p)[2] = (*p)[2].wrapping_add(mpu);
    }
}

pub fn bill_audio_sources(parts: [u64; 4]) {
    unsafe {
        let p = &raw mut AUDIO_SOURCE_PARTS;
        for (i, part) in parts.into_iter().enumerate() {
            (*p)[i] = (*p)[i].wrapping_add(part);
        }
    }
}

pub fn bill_present() {
    unsafe {
        let p = &raw mut PRESENTS;
        *p = (*p).wrapping_add(1);
    }
}

/// Timer acquisition, device tick loop, display, audio, and the tick count —
/// each can be billed independently and divided by its own denominator.
pub fn bill_slice2(take: u64, timer_cyc: u64, display: u64, audio: u64, advances: u64) {
    unsafe {
        let p = &raw mut SLICE_PARTS;
        (*p)[0] = (*p)[0].wrapping_add(take);
        (*p)[1] = (*p)[1].wrapping_add(timer_cyc);
        (*p)[2] = (*p)[2].wrapping_add(display);
        (*p)[3] = (*p)[3].wrapping_add(audio);
        (*p)[4] = (*p)[4].wrapping_add(advances);
    }
}

/// Is the periodic `[prof]` dump on? Written by the F12 monitor, read by the
/// event loop — the same single-threaded volatile-flag shape as
/// the window picker's atomic target.
static mut PROFILE_DUMP: bool = false;

/// Toggle the profile dump and report its new state.
pub fn toggle_profile() {
    let on = unsafe {
        let v = !core::ptr::read_volatile(&raw const PROFILE_DUMP);
        core::ptr::write_volatile(&raw mut PROFILE_DUMP, v);
        v
    };
    crate::println!("[prof] cycle profiling {}", if on { "ON" } else { "off" });
}

pub fn profile_enabled() -> bool {
    unsafe { core::ptr::read_volatile(&raw const PROFILE_DUMP) }
}

/// Runtime syscall-trace gate, consulted by both `dos_trace!` (DOS/DPMI) and
/// `linux_trace!` (Linux). Distinct from [`profile_enabled`]: that's the
/// periodic cycle profiler, this is per-syscall log lines. Toggled by the F12
/// monitor's Trace item, and bracketed by COMMAND.COM around a child exec (INT
/// 31h synth AH=02/03) so a log captures just that program. Default OFF so
/// boot/init/DN startup stay silent until something enables it.
static mut SYSCALL_TRACE: bool = false;

/// Set the trace gate directly (the COMMAND.COM bracket path).
pub fn set_trace(on: bool) {
    unsafe { core::ptr::write_volatile(&raw mut SYSCALL_TRACE, on) };
}

/// Toggle syscall tracing, reporting which way it went (the F12 Trace item).
pub fn toggle_trace() {
    let on = unsafe {
        let v = !core::ptr::read_volatile(&raw const SYSCALL_TRACE);
        core::ptr::write_volatile(&raw mut SYSCALL_TRACE, v);
        v
    };
    crate::println!("[trace] syscall tracing {}", if on { "ON" } else { "off" });
}

pub fn trace_enabled() -> bool {
    unsafe { core::ptr::read_volatile(&raw const SYSCALL_TRACE) }
}

struct EventStats {
    iterations: u64,
    min_free: usize,
    last_free: usize,
    user_cycles: u64,
    kernel_cycles: u64,
    /// Kernel time split by phase, to localize it: `pre` is the per-event
    /// world-advance before the guest runs (advance_world, console drain,
    /// after_input); `post` is dispatch + scheduler afterwards.
    pre_cycles: u64,
    post_cycles: u64,
    /// Cycles spent in `dispatch` per event kind — the same 11 slots as
    /// `counts`, so dividing one by the other gives cost-per-event.
    dispatch_cycles: [u64; 11],
    /// Exact pre-run routine split: event bookkeeping/OSD, hardware IRQ drain,
    /// advance_world, console dispatch, personality after_input.
    pre_parts: [u64; 5],
    part_mark: u64,
    slice_start: u64,
    last_idx: usize,
    last_kernel_entry: u64,
    guest_entry_cs: u16,
    guest_entry_ip: u32,
    guest_entry_flags: u32,
    longest_guest_cycles: u64,
    longest_guest_entry_cs: u16,
    longest_guest_entry_ip: u32,
    longest_guest_entry_flags: u32,
    longest_guest_exit_cs: u16,
    longest_guest_exit_ip: u32,
    longest_guest_exit_flags: u32,
    longest_guest_exit_kind: usize,
    last_profile_dump: u64,
    last_allocations: u32,
    last_deallocations: u32,
    counts: [u32; 11], // irq, softint, hlt, in, out, ins, outs, fault, pf, exc, syscall
    /// Port I/O by PORT — a small associative table rather than a 64K array,
    /// which would not fit the kernel stack. Ports that matter are few; once
    /// the table is full the rest aggregate into `port_other`.
    ports: [(u16, u32, u64); 12], // (port, accesses, dispatch cycles)
    port_other: u32,
    last_port: Option<u16>,
    /// Software interrupts BY VECTOR. The aggregate above says the guest is
    /// trapping a lot; only this says which service it is asking for, which is
    /// the difference between a number and a lead.
    softint_by_vec: [u32; 256],
}

impl EventStats {
    /// Sampling cadence for the free-page low-water mark.
    const MEM_DUMP_PERIOD: u64 = 1000;
    /// Profile dump cadence. Roughly assume 2 GHz host; only used to format
    /// the dump as seconds. Off by a constant factor but the ratio is exact.
    const PROFILE_DUMP_CYCLES: u64 = 2_000_000_000;
    fn new<A: crate::Arch>(machine: &mut A) -> Self {
        let free = machine.free_page_count();
        let now = machine.rdtsc();
        let (allocations, deallocations) = lib::heap::allocation_counts();
        EventStats {
            iterations: 0,
            min_free: free,
            last_free: free,
            user_cycles: 0,
            kernel_cycles: 0,
            pre_cycles: 0,
            post_cycles: 0,
            dispatch_cycles: [0; 11],
            pre_parts: [0; 5],
            part_mark: 0,
            slice_start: 0,
            last_idx: 0,
            last_kernel_entry: now,
            guest_entry_cs: 0,
            guest_entry_ip: 0,
            guest_entry_flags: 0,
            longest_guest_cycles: 0,
            longest_guest_entry_cs: 0,
            longest_guest_entry_ip: 0,
            longest_guest_entry_flags: 0,
            longest_guest_exit_cs: 0,
            longest_guest_exit_ip: 0,
            longest_guest_exit_flags: 0,
            longest_guest_exit_kind: 0,
            last_profile_dump: now,
            last_allocations: allocations,
            last_deallocations: deallocations,
            counts: [0; 11],
            ports: [(0, 0, 0); 12],
            port_other: 0,
            last_port: None,
            softint_by_vec: [0; 256],
        }
    }

    /// Called right after `dispatch` returns: bills its cost to the event kind
    /// that caused it, so cost-per-event falls out of cycles/count.
    fn after_dispatch<A: crate::Arch>(&mut self, machine: &mut A) {
        let now = machine.rdtsc();
        let spent = now.wrapping_sub(self.last_kernel_entry);
        self.dispatch_cycles[self.last_idx] =
            self.dispatch_cycles[self.last_idx].wrapping_add(spent);
        self.bill_port(spent);
    }

    /// Top of the loop: everything from here to `pre_run` is the per-event
    /// world-advance.
    fn slice_begin<A: crate::Arch>(&mut self, machine: &mut A) {
        let now = machine.rdtsc();
        // Whatever ran since the last post_run was dispatch + scheduler.
        self.post_cycles = self
            .post_cycles
            .wrapping_add(now.wrapping_sub(self.last_kernel_entry));
        self.slice_start = now;
        self.part_mark = now;
    }

    /// Close out one part of the pre-phase and open the next.
    fn part<A: crate::Arch>(&mut self, machine: &mut A, i: usize) {
        // The extra routine boundaries exist only for an active profile.
        // Normal gameplay keeps the old event-loop instruction count.
        if !profile_enabled() {
            return;
        }
        let now = machine.rdtsc();
        self.pre_parts[i] = self.pre_parts[i].wrapping_add(now.wrapping_sub(self.part_mark));
        self.part_mark = now;
    }

    fn iteration<A: crate::Arch>(&mut self, machine: &mut A) {
        self.iterations = self.iterations.wrapping_add(1);
        if self.iterations.is_multiple_of(Self::MEM_DUMP_PERIOD) {
            let free = machine.free_page_count();
            if free < self.min_free {
                self.min_free = free;
            }
            self.last_free = free;
        }
    }

    fn pre_run<A: crate::Arch>(&mut self, machine: &mut A, regs: &Regs) {
        let now = machine.rdtsc();
        self.pre_cycles = self
            .pre_cycles
            .wrapping_add(now.wrapping_sub(self.slice_start));
        self.kernel_cycles = self
            .kernel_cycles
            .wrapping_add(now.wrapping_sub(self.last_kernel_entry));
        self.last_kernel_entry = now;
        if profile_enabled() {
            self.guest_entry_cs = regs.code_seg();
            self.guest_entry_ip = regs.ip32();
            self.guest_entry_flags = regs.flags32();
        }
    }

    /// Tally one port access. Linear scan of a 12-entry table: shorter than a
    /// cache line's worth of work, and the hot set is a handful of ports.
    fn count_port(&mut self, port: u16) {
        self.last_port = Some(port);
        for e in self.ports.iter_mut() {
            if e.1 == 0 || e.0 == port {
                e.0 = port;
                e.1 += 1;
                return;
            }
        }
        self.port_other += 1;
    }

    /// Bill dispatch cycles to the port that caused them, so an expensive
    /// HANDLER is distinguishable from a merely popular port.
    fn bill_port(&mut self, cycles: u64) {
        let Some(port) = self.last_port.take() else {
            return;
        };
        for e in self.ports.iter_mut() {
            if e.0 == port && e.1 != 0 {
                e.2 = e.2.wrapping_add(cycles);
                return;
            }
        }
    }

    fn post_run<A: crate::Arch>(
        &mut self,
        machine: &mut A,
        kevent: &crate::KernelEvent,
        regs: &Regs,
    ) {
        use crate::KernelEvent as KE;
        let now = machine.rdtsc();
        let guest_cycles = now.wrapping_sub(self.last_kernel_entry);
        self.user_cycles = self.user_cycles.wrapping_add(guest_cycles);
        self.last_kernel_entry = now;
        let idx = match kevent {
            KE::Irq => 0,
            KE::SoftInt(n) => {
                // Every IVT slot is a 2-byte `INT 31h` stub, so the event's own
                // vector is always 31h — the trampoline, not the service. The
                // service is the slot the guest landed in, which `rm_vector_
                // dispatch` recovers the same way: (ip - 2) / 2.
                let vec = if regs.code_seg() == crate::kernel::dos::stub_seg() {
                    (regs.ip32().wrapping_sub(2) / 2) as u8
                } else {
                    *n
                };
                self.softint_by_vec[vec as usize] += 1;
                1
            }
            KE::Hlt => 2,
            KE::In { port, .. } => {
                self.count_port(*port);
                3
            }
            KE::Out { port, .. } => {
                self.count_port(*port);
                4
            }
            KE::Ins { .. } => 5,
            KE::Outs { .. } => 6,
            KE::Fault => 7,
            KE::PageFault { .. } => 8,
            KE::Exception(_) => 9,
            KE::Syscall => 10,
            KE::VifWindow { .. } | KE::VifStep => 1,
        };
        if profile_enabled() && guest_cycles > self.longest_guest_cycles {
            self.longest_guest_cycles = guest_cycles;
            self.longest_guest_entry_cs = self.guest_entry_cs;
            self.longest_guest_entry_ip = self.guest_entry_ip;
            self.longest_guest_entry_flags = self.guest_entry_flags;
            self.longest_guest_exit_cs = regs.code_seg();
            self.longest_guest_exit_ip = regs.ip32();
            self.longest_guest_exit_flags = regs.flags32();
            self.longest_guest_exit_kind = idx;
        }
        self.counts[idx] += 1;
        self.last_idx = idx;
        if now.wrapping_sub(self.last_profile_dump) >= Self::PROFILE_DUMP_CYCLES {
            if profile_enabled() {
                let total = self.user_cycles.wrapping_add(self.kernel_cycles);
                let pct10 = |v: u64| {
                    v.saturating_mul(1000)
                        .checked_div(total.max(1))
                        .unwrap_or(0)
                };
                // Average dispatch cost for the two hottest event kinds.
                let cost = |i: usize| -> u64 {
                    self.dispatch_cycles[i]
                        .checked_div(self.counts[i].max(1) as u64)
                        .unwrap_or(0)
                };
                let c = &self.counts;
                // The three hottest vectors, so a polling loop names itself.
                let mut top = [(0u32, 0usize); 3];
                for (v, &n) in self.softint_by_vec.iter().enumerate() {
                    if n > top[2].0 {
                        top[2] = (n, v);
                        top.sort_by_key(|e| core::cmp::Reverse(e.0));
                    }
                }
                let ev = self.iterations.max(1);
                let dispatch_total = self
                    .dispatch_cycles
                    .iter()
                    .fold(0u64, |sum, &v| sum.wrapping_add(v));
                let scheduler_total = self.post_cycles.saturating_sub(dispatch_total);
                let sp = unsafe { SLICE_PARTS };
                let dp = unsafe { DISP_PARTS };
                let dm = unsafe { core::ptr::read_volatile(&raw const DISP_MODE) };
                let ap = unsafe { AUDIO_PARTS };
                let asp = unsafe { AUDIO_SERVICE_PARTS };
                let asrc = unsafe { AUDIO_SOURCE_PARTS };
                let np = unsafe { PRESENTS };
                let loop_total = self.pre_parts[0]
                    .wrapping_add(self.pre_parts[3])
                    .wrapping_add(self.pre_parts[4]);
                let world_other = self.pre_parts[2].saturating_sub(
                    sp[0]
                        .saturating_add(sp[1])
                        .saturating_add(sp[2])
                        .saturating_add(sp[3]),
                );
                let accounted = sp[2]
                    .saturating_add(sp[3])
                    .saturating_add(dispatch_total)
                    .saturating_add(self.pre_parts[1])
                    .saturating_add(loop_total)
                    .saturating_add(scheduler_total)
                    .saturating_add(world_other);
                let other = self.kernel_cycles.saturating_sub(accounted);
                let user = pct10(self.user_cycles);
                let kernel = pct10(self.kernel_cycles);
                crate::dbg_println!(
                    "[prof] CPU: guest={}.{}% kernel={}.{}% ticks={} at={:04X}:{:08X}",
                    user / 10,
                    user % 10,
                    kernel / 10,
                    kernel % 10,
                    machine.get_ticks(),
                    regs.code_seg(),
                    regs.ip32()
                );
                let display = pct10(sp[2]);
                let audio = pct10(sp[3]);
                let dispatch = pct10(dispatch_total);
                let irq_drain = pct10(self.pre_parts[1]);
                let loop_pct = pct10(loop_total);
                let clock_pct = pct10(self.pre_parts[0]);
                let console_pct = pct10(self.pre_parts[3]);
                let after_input_pct = pct10(self.pre_parts[4]);
                let sched = pct10(scheduler_total);
                let world = pct10(world_other);
                let other_pct = pct10(other);
                crate::dbg_println!(
                    "[prof] kernel: display={}.{}% audio={}.{}% dispatch={}.{}% irq-drain={}.{}% loop={}.{}% sched={}.{}% world-other={}.{}% other={}.{}%",
                    display / 10,
                    display % 10,
                    audio / 10,
                    audio % 10,
                    dispatch / 10,
                    dispatch % 10,
                    irq_drain / 10,
                    irq_drain % 10,
                    loop_pct / 10,
                    loop_pct % 10,
                    sched / 10,
                    sched % 10,
                    world / 10,
                    world % 10,
                    other_pct / 10,
                    other_pct % 10
                );
                crate::dbg_println!(
                    "[prof] loop: clock={}.{}% console={}.{}% after-input={}.{}%",
                    clock_pct / 10,
                    clock_pct % 10,
                    console_pct / 10,
                    console_pct % 10,
                    after_input_pct / 10,
                    after_input_pct % 10
                );
                let scanout = pct10(dp[0]);
                let render = pct10(dp[2]);
                let present = pct10(dp[3]);
                let per_frame = |v: u64| v.checked_div(np.max(1)).unwrap_or(0);
                crate::dbg_println!(
                    "[prof] display: {:?} | {} frames, {} renders, {} px/frame | scanout={}.{}% render={}.{}% present={}.{}% | cycles/frame render={} present={}",
                    dm,
                    np,
                    dp[1],
                    dp[4].checked_div(np.max(1)).unwrap_or(0),
                    scanout / 10,
                    scanout % 10,
                    render / 10,
                    render % 10,
                    present / 10,
                    present % 10,
                    per_frame(dp[2]),
                    per_frame(dp[3])
                );
                let devices = pct10(ap[0]);
                let setup = pct10(ap[1]);
                let pump = pct10(ap[2]);
                let clocks = pct10(ap[3]);
                crate::dbg_println!(
                    "[prof] audio: pump={}.{}% devices={}.{}% setup={}.{}% clocks/irqs={}.{}% | generated={} frames",
                    pump / 10,
                    pump % 10,
                    devices / 10,
                    devices % 10,
                    setup / 10,
                    setup % 10,
                    clocks / 10,
                    clocks % 10,
                    ap[4]
                );
                crate::dbg_println!(
                    "[prof] audio service: sb={}c gus={}c mpu={}c",
                    asp[0],
                    asp[1],
                    asp[2]
                );
                crate::dbg_println!(
                    "[prof] audio sources: sb={}c gus={}c mpu={}c speaker={}c",
                    asrc[0],
                    asrc[1],
                    asrc[2],
                    asrc[3]
                );
                crate::dbg_println!(
                    "[prof] exits: {} total | softint={}@{}c in={}@{}c out={}@{}c irq={}@{}c pf={} syscall={}",
                    ev,
                    c[1],
                    cost(1),
                    c[3],
                    cost(3),
                    c[4],
                    cost(4),
                    c[0],
                    cost(0),
                    c[8],
                    c[10]
                );
                let event_names = [
                    "irq",
                    "softint/vif",
                    "hlt",
                    "in",
                    "out",
                    "ins",
                    "outs",
                    "fault",
                    "page-fault",
                    "exception",
                    "syscall",
                ];
                crate::dbg_println!(
                    "[prof] longest guest={}c entry={:04X}:{:08X} flags={:08X} (VIF={}) exit={:04X}:{:08X} flags={:08X} (VIF={}) via {}",
                    self.longest_guest_cycles,
                    self.longest_guest_entry_cs,
                    self.longest_guest_entry_ip,
                    self.longest_guest_entry_flags,
                    (self.longest_guest_entry_flags >> 19) & 1,
                    self.longest_guest_exit_cs,
                    self.longest_guest_exit_ip,
                    self.longest_guest_exit_flags,
                    (self.longest_guest_exit_flags >> 19) & 1,
                    event_names[self.longest_guest_exit_kind]
                );
                let fixed = loop_total
                    .saturating_add(self.pre_parts[1])
                    .checked_div(ev)
                    .unwrap_or(0);
                crate::dbg_println!(
                    "[prof] per-exit fixed={}c (loop={} irq-drain={}) | world: advances={} timer={}c/advance unclassified={} cycles",
                    fixed,
                    loop_total / ev,
                    self.pre_parts[1] / ev,
                    sp[4],
                    sp[1].checked_div(sp[4].max(1)).unwrap_or(0),
                    world_other
                );
                let (allocations, deallocations) = lib::heap::allocation_counts();
                crate::dbg_println!(
                    "[prof] heap: allocations={} (+{}) deallocations={} (+{}) live={}",
                    allocations,
                    allocations.wrapping_sub(self.last_allocations),
                    deallocations,
                    deallocations.wrapping_sub(self.last_deallocations),
                    allocations.wrapping_sub(deallocations)
                );
                unsafe { SLICE_PARTS = [0; 5] };
                unsafe { DISP_PARTS = [0; 5] };
                unsafe { AUDIO_PARTS = [0; 5] };
                unsafe { AUDIO_SERVICE_PARTS = [0; 3] };
                unsafe { AUDIO_SOURCE_PARTS = [0; 4] };
                unsafe { PRESENTS = 0 };
                if c[3] + c[4] > 0 {
                    let mut p = self.ports;
                    p.sort_by_key(|e| core::cmp::Reverse(e.1));
                    let per = |e: (u16, u32, u64)| e.2.checked_div(e.1.max(1) as u64).unwrap_or(0);
                    crate::dbg_println!(
                        "[prof] ports: {:03X}h={}@{}c {:03X}h={}@{}c {:03X}h={}@{}c {:03X}h={}@{}c {:03X}h={}@{}c other={}",
                        p[0].0,
                        p[0].1,
                        per(p[0]),
                        p[1].0,
                        p[1].1,
                        per(p[1]),
                        p[2].0,
                        p[2].1,
                        per(p[2]),
                        p[3].0,
                        p[3].1,
                        per(p[3]),
                        p[4].0,
                        p[4].1,
                        per(p[4]),
                        self.port_other
                    );
                }
                if c[1] > 0 {
                    crate::dbg_println!(
                        "[prof] hottest INT (service, not the 31h trampoline): {:02X}h={} {:02X}h={} {:02X}h={}",
                        top[0].1,
                        top[0].0,
                        top[1].1,
                        top[1].0,
                        top[2].1,
                        top[2].0
                    );
                }
                // Disk I/O volume and average request size.
                let io = crate::kernel::iostat::snapshot();
                if io.vol_reads > 0 {
                    crate::dbg_println!(
                        "[io] reads={} ({} sectors, {} sec/read)",
                        io.vol_reads,
                        io.vol_sectors,
                        io.vol_sectors.checked_div(io.vol_reads).unwrap_or(0),
                    );
                }
                crate::kernel::iostat::reset();
            }
            let (allocations, deallocations) = lib::heap::allocation_counts();
            self.last_allocations = allocations;
            self.last_deallocations = deallocations;
            self.user_cycles = 0;
            self.kernel_cycles = 0;
            self.pre_cycles = 0;
            self.post_cycles = 0;
            self.dispatch_cycles = [0; 11];
            self.pre_parts = [0; 5];
            self.counts = [0; 11];
            self.softint_by_vec = [0; 256];
            self.ports = [(0, 0, 0); 12];
            self.port_other = 0;
            self.longest_guest_cycles = 0;
            self.last_profile_dump = now;
            self.iterations = 0;
            // Emitting the report can be expensive (notably klog line
            // capture). It is profiler overhead, not dispatch or scheduler
            // work for the event that happened to cross the dump deadline.
            // Re-open kernel timing after it so neither this event nor the
            // next window is charged for printing the previous window.
            if profile_enabled() {
                self.last_kernel_entry = machine.rdtsc();
            }
        }
    }
}

fn trim_ascii(s: &[u8]) -> &[u8] {
    let start = s.iter().position(|&c| c > b' ').unwrap_or(s.len());
    let end = s.iter().rposition(|&c| c > b' ').map_or(start, |i| i + 1);
    &s[start..end]
}
