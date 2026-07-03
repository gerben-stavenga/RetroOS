# Projects

Larger architectural work / refactors (distinct from the per-game bug sprint
below). These are sizable, multi-step efforts.

**Guiding goal:** one kernel that supports all hardware from the 386 to today,
giving retro devices (VGA, Sound Blaster, …) **direct/passthrough access when
the real device is available** and **emulating them when absent or when
emulation is preferred** — the same kernel adapts per-machine rather than
forking. Several projects below (1, 4) are concrete expressions of this.

## 1. Hosted backend: audio + video (DOSBox-equivalent)
Turn the hosted/interp backend into a graphical emulator so RetroOS-hosted runs
DOS games like DOSBox (its own kernel underneath, not a bespoke DOS layer).
- [ ] **Real-time audio.** The canonical audio port window (0x530/0x532/0x534)
      already receives i16-stereo frames (today → WAV). Add a real-time host
      sink (ring buffer → audio callback) to play to speakers.
- [x] **Graphical window.** Done via the single-VGA design: the kernel
      emulates the VGA once (`machine/vga.rs`: VgaState as the live register
      file when no card, `display_tick` rendering through `lib::vga_render`
      at divided tick cadence) and presents through a platform sink
      (`lib::vga_render::set_present_sink`) — hosted parks frames in the
      backend mailbox for the retroos-play window; metal blits into the
      fbcon GOP framebuffer. arch-interp's own VGA emulation is deleted.
- [ ] **Input.** Window keyboard events + **mouse** (→ the existing INT 33h
      packet path). Keyboard already flows `stdin → post_irq`.
- [ ] **Threading.** Window/event loop on the main thread, interp CPU on a
      worker thread, sharing guest RAM (framebuffer), `post_irq` (input), an
      audio ring. Small restructure of `kernel/src/main.rs` (CPU runs on main
      today).
- [ ] **Decision: host library** — SDL2 (mature, C dep, what DOSBox uses) vs
      pure-Rust (minifb + cpal) vs winit + pixels + cpal. Hosted-only, so it
      doesn't touch the metal/Bazel side.

## 2. Per-thread / per-personality TSS I/O bitmap
The TSS32 IOPB is a single **shared** bitmap (all threads); `allow_io_ports`
(OPL un-trap on SB passthrough) is therefore global. It works today only because
card presence is machine-wide.
- [x] Make I/O trapping **per-thread / per-personality** (f755094):
      `kernel::io_policy` rebuilds the bitmap on every swap-in from
      (personality, Platform, focus). DOS-with-focus gets the VGA window on a
      real card; background DOS gets only granted device windows (OPL stays
      DOS-global so background music keeps playing); Linux gets nothing — its
      dispatcher already faults KE::In/Out, and now the trap actually fires.
      Arch mechanism = `reset_io_bitmap` + `allow_io_ports`; policy in kernel.
- [x] `kernel::platform` (a4fc2ae): the machine probed ONCE at startup into
      ADTs — Host { Qemu | Metal | Interp }, Display { VgaCard | Framebuffer
      | HostWindow | Headless }, Firmware { NativeBios | Substitute },
      DebugSink. Killed the lazy vga_present atomic, the reset-vector sniff
      at BIOS install, and HOST_QEMU/is_qemu().

## 2b. Decouple focus from execution
`kernel::focus` (f755094) names the concept: F11 moves console ownership
(display + keyboard + mouse), release/acquire hooks do the screen handoff,
and the I/O bitmap follows the owner. But today the event loop still runs
only the focused thread — focus and execution move together.
- [x] **Factorization groundwork (d8a5f98..6fd8120, behavior-preserving):**
      kernel::console (input routing to the console owner, F11/F12
      interception, blocked-stdin path), kernel::exec_ctx::ExecutionContext
      (the CPU loan: seed/run/switch_to — pure execution swap, io_policy
      derived inside; focus deliberately outside), Personality::on_slice /
      after_input (DOS virtual time + IRQ delivery, Linux pending-IO),
      kernel::sched (the policy stated once: the focused thread runs;
      next_after + focus_request), EventStats (loop diagnostics). Today's
      focus-follows-execution coupling lives in ONE place:
      startup::switch_focus_and_run. Verified: TCC byte-identical, Bochs
      UEFI DN, hosted DiskRoot/HostRoot, 15-window PRINCE sweep clean.
- [ ] Scheduler change: background threads keep executing while an
      unfocused DOS app renders into its own VgaState and gets no input.
      Everything keyed off `focus::focused()` is already in place; the event
      loop needs to multiplex Ready threads instead of parking on the
      focused one. Watch the DN swap-cycle DPMI bug (see bug sprint) — it
      lives in exactly this machinery.
- [ ] Route keyboard/mouse explicitly through `focus::focused()` instead of
      "whoever is running" (equivalent today, load-bearing after the
      scheduler change).

## 2c. Cleanup roadmap (post event-loop factoring, in attack order)
Same doctrine: one concept per seam, policy stated once. Surveyed 2026-06-11.
- [ ] **Process lifecycle.** `handle_fork_exec` predates ExecutionContext:
      raw double machine.switch_to with a hand-saved `saved_cpu` juggle,
      parent snapshot dance, personality-specific child wiring inline. Wants
      a scoped `ctx.borrow_space(child_tid, |…|)` primitive (enter/do/restore
      as a structural guarantee) + child setup on Personality. Also:
      exit_thread's parent-wake protocol is an inline Dos/Linux match →
      `Personality::on_child_exit`; sched's Fork/Exec arms are TODO stubs.
- [ ] **Finish the sched seam (small).** yield_thread / cycle_next /
      schedule are policy fragments still in thread.rs; move to sched.rs —
      thread.rs = table + lifecycle, sched.rs = ALL the policy.
- [ ] **Console output side.** Input has a router; output is scattered:
      vga.rs console state, the KERNEL_OWNS_SCREEN atomic flipped in
      run_dos_program, per-backend debug sinks, fbcon flush hooks. The
      ownership flag is a focus-shaped concept (kernel owns the screen until
      the first program takes it) — type the handoff like input.
- [ ] **DOS port dispatch.** machine/mod.rs emulate_inb/outb is a long match
      with vga_present() interleaved per arm — passthrough-vs-emulated
      decided per-port instead of per-device. Canonicalize: port range →
      device, each device knowing its mode from the Platform verdict.
      Touches game paths — run the sweep per step.
- [ ] **dos/dos.rs (later, big).** 3800 lines of INT 21 dispatcher + the
      exec/swap-cycle machinery. Highest value, highest risk — only with a
      thicker regression suite.

## 3. Better kernel init structure
`startup.rs` does too much inline — TAR/ext4 mounts, CONFIG.SYS, AC'97 probe,
hostfs, the cmdline/DN dispatch, the boot self-build — in one long function.
- [x] Restructured (ee9ab48): startup() is an ordered spine — heap →
      platform probe → threading → block → mount_filesystems →
      init_device_policy → load_master_env → init_console_pipe → run. Both
      entry points (metal enter_ring1, hosted main) share it.

## 4. Audio into the Platform type (follow-up to 2/3)
- [x] Done (36a8ad4): `platform::Audio { SbPassthrough | EmulatedAc97 |
      EmulatedPortWindow | EmulatedSilent }` probed once (uniform across
      backends). ensure_mode/SbMode, sound's device_present atomic, and the
      io_policy grant table all died; OPL is derived template data; ac97
      split into scan (probe) + init (bring-up, gated on the verdict).
      Remaining audio work lives with the SB DSP/mixer/8237 model itself
      (synthesis for OPL, see `project_dma_zero_copy_design`).

## 5. Boot media into the Platform type (follow-up to 2/3)
- [x] Done (04eb600): `platform::Media { DiskRoot{tar_lba, ext4_lba,
      hostfs} | HostRoot | Diskless }` probed once (the MBR scan + hostfs
      transport feed the verdict; the payload IS the mount plan).
      DOSBox-style works: `retroos-host --host DIR --cmd "X.COM …"` boots
      imageless with the host directory as the root drive.
- [x] **Bootfs embedded in retroos-host** (same objcopy-symbols mechanism
      as the metal kernel; retroos-host-bare twin for the TCC genrules
      breaks the COMMAND.COM cycle; retro_platform.bzl transition pins the
      bootfs subtree to the canonical platform). /boot is an invariant —
      `retroos-host --host DIR` boots DN from a bare folder.
- [ ] **Honest hostfs probe.** `hostfs::init` answers "a COM1 UART
      exists" — true on Bochs/QEMU with nothing behind it (now visible as
      `hostfs: true` in the typed verdict; /host is dead there, as it
      always was). A transport handshake (hello/ack with the host agent)
      would make the verdict mean what it says.

## 6. UEFI boot + DOS personality owns its BIOS
UEFI machines have no legacy real-mode BIOS (no INT 10h/16h/08h/… services, no
F-segment ROM). To run DOS guests there, RetroOS must supply its own BIOS — the
same situation the interpreter already has (no ROM).
- [x] **DN runs with full display on the UEFI mock** (the milestone the items
      below add up to): GRUB multiboot → embedded bootfs → Rust BIOS →
      kernel-emulated VGA → GOP framebuffer. Two metal-specific fixes it
      took: OVMF leaves the LAPIC enabled with LINT0 masked, eating every
      PIC interrupt (`init_interrupts` disables xAPIC or programs x2APIC
      LINT0 for virtual-wire ExtINT routing); and the display render needed a
      tick divider + identical-frame skip (uncached GOP blits at full tick
      rate starved the guest).
      Remaining for real hardware: keyboard on the mock is wired
      (i8042 → IRQ1 → Rust BIOS INT 09) but untested interactively; xHCI for
      laptops with no i8042.
- [x] **GOP framebuffer console** — the kernel's multiboot header requests a
      linear framebuffer (video fields, bit 2); `kernel/src/arch/fbcon.rs`
      maps it (cache-disabled, `paging2::FB_WINDOW_*`) and renders dirty text
      cells via `lib::vga_render::render_text_cell` after each console write
      (`lib::vga::set_text_flush`). Kernel console is visible on the
      `run_uefi.sh` mock; legacy boots keep writing real B8000 cells.
      Gotcha for `boot-uefi` later: GRUB places the multiboot color_info at
      offset 112, not the spec's 110 (multiboot.h's union is 4-aligned).
- [x] **The DOS personality owns its BIOS** (`kernel/src/kernel/dos/bios.rs`):
      the 16-bit C BIOS is gone from arch-interp, replaced by Rust services
      dispatched from the ONE 256-slot stub array, which now has two RM
      *views* separated purely by segment aliasing (the RM twin of PM's
      VECTOR_STUB_SEL vs SPECIAL_STUB_SEL): `STUB_SEG:vec*2` = vector view
      (slot == INT vector, all 256 IVT entries; kernel-DOS syscall vectors +
      BIOS services + IRET/EOI defaults), `CTRL_STUB_SEG(0):STUB_BASE+slot*2`
      = control view (XMS/DPMI entries, RM callbacks, resume parks — same
      offset arithmetic as the PM selectors). No second array, no slot/vector
      collision constraints, and "is INT n hooked?" is an IVT-segment
      compare. The BDA is a typed Rust projection at 0x400 (offset_of!, no
      magic addresses). Installed by `setup_ivt` whenever no native ROM is
      present (no far-JMP at F000:FFF0): interp today, UEFI metal for free.
      Port I/O goes through `machine::emulate_inb/outb` (the vpic/vkbd are
      kernel-side — a raw Arch outb bypasses the vpic and freezes ticks;
      SkyRoads black-screen was the reproducer). Verified: SkyRoads render +
      palette identical to the C BIOS, in-OS TCC byte-identical, DOSRT
      (DPMI entry/callbacks) and BCC+TLINK (16-bit DPMI client + EXEC) clean,
      DN TUI, legacy metal untouched, diskless + UEFI boots green.
- [x] **Embedded bootfs — kernel.elf is a complete system.** DN + COMMAND.COM
      + a fallback CONFIG.SYS ride inside the kernel image (`//:bootfs_tar` →
      objcopy → linked into .rodata; `kernel::bootfs()`); startup mounts it at
      /boot when no TAR partition exists. COMMAND.COM is a Bazel artifact now
      (in-OS TCC on the interpreter, `//apps-boot/command:command_com`) — the
      per-boot self-build is gone; it also ships at C:\COMMAND.COM on ext4.
      The boot kernel mapping grew 1MB→5MB (pt_kernel2/3) to fit. Verified:
      `qemu-system-i386 -kernel kernel.elf` with NO disk boots to DN.
- [ ] **Re-evaluate bootfs size vs the kernel ≤ 1MB design line.** Numbers:
      kernel proper = 954KB loaded (only ~70KB headroom under 1MB); bootfs =
      1060KB, dominated by DN.OVR (746KB, the TP overlay body — not
      trimmable); gzip -9 → ~512KB. Options when revisiting: (a) embed
      COMMAND.COM only (~975KB total, revert pt_kernel2/3), DN from disk;
      (b) gzipped DN+COMMAND (~1.4MB, needs a no_std inflate in the kernel);
      (c) keep as-is (2.05MB loaded). Also note ~100KB of cheap kernel diet
      if headroom is ever needed: core::fmt float machinery (exp_u128 /
      POWER_OF_FIVE_128 / f128 soft-float, ~30KB) and the fixed 65KB kpipe
      pool.
- [ ] **UEFI/modern-metal boot = the user's existing GRUB** (direction change:
      no own `boot-uefi` entry — GRUB is on people's machines already and
      multiboot is our production boot contract there). The menuentry snippet
      is documented in BOOTING.md (copy kernel.elf, insmod efi_gop, Secure
      Boot off). Remaining: a story for reaching the user's storage from
      RetroOS (GPT scan, or stay RAM-only diskless), and the real-laptop
      trial itself (open questions: panel GOP pixel format, i8042 presence).

## 7. Real-laptop boot reset after "Heap initialized" (RESOLVED 2026-07-03)
The laptop resets silently right after the "Heap initialized" print — no
panic, no double-fault dump, machine just reboots. Same kernel boots fine on
QEMU UEFI, Bochs+OVMF (`run_uefi_bochs.sh`), and hosted. Eliminated so far:
port-0x80 side effects (delays removed entirely, still resets), and
"handler couldn't run" (an IST1 double-fault handler now prints+halts for
that whole class — yet the reset stays silent, so the machine dies without a
deliverable CPU fault: smells like a write to firmware/SMM-owned memory the
multiboot map called free, or something interrupt/time-driven).
- [x] **Get the countdown verdict.** The instrumented kernel (local branch
      `metal-work`) prints a 10×1s spin countdown with zero memory activity,
      then `demand[k]: va=… → phys …` for the first 16 heap pages, each line
      lingering ~2s before the page is touched. Where the output stops picks
      the cause: mid-countdown = interrupt/time-driven (memory innocent);
      after `probe: start` with no demand line = fault-entry path; after
      `demand[k]` = that physical address is poison (cross-check against the
      `Memory regions:` list printed at the top of boot — photograph both).
- [ ] **Rebase `metal-work` onto master afterwards.** Its build plumbing
      (build_host.sh inputs fix) is superseded by the crate_universe work on
      master. Keepers to land regardless of the bug: the IST1 double-fault
      handler (arch-metal descriptors/traps), the Bochs UEFI rig
      (`run_uefi_bochs.sh` + `vncstub.py`, 2MB-OVMF auto-fetch,
      `reset_on_triple_fault=0`), and whichever probe caught the bug. The
      diagnostics knobs (`HEAP_PROBE_MB`, `DEMAND_TRACE_N`) go back to 0.

## 8. Build/toolchain cleanups
- [ ] **Upstream the pre-generated unicorn bindings into the fork.** The
      86KB `toolchain/unicorn-sys-pregen-bindings.patch` vendors bindgen's
      output and rewires `include!`; committing `bindings_pregen.rs` to
      `unicorn-retroos-patch` (plus the include! change) lets this repo drop
      the patch to a one-liner or nothing. Regeneration story stays the
      crate's own `generate_bindings` when `unicorn.h` changes.
- [ ] **Watch the rules_python stale-repo trap.** The rules_foreign_cc dep
      bumped transitive rules_python; an interrupted fetch left a stale
      hermetic-python external repo and `pkg_tar` failed on a dangling
      setuptools file. Remedy (documented in 7aab93a): delete the
      `rules_python~~python~*` external dir + `.marker`, rebuild.

## 9. arch-interp translation-cache coherence (stale-TB class) (RESOLVED)
Root cause of the long-standing "DN file-panel Enter can't launch digger" bug
(Borland RTE 204): the interp loads guest **code** host-side — DOS overlay/EXE
loads, relocations, BSS go through `vcpu.rs` `GuestBytes` (`host.write_volatile`),
which bypasses Unicorn's self-modifying-code detection. Unicorn kept executing a
**stale translation block** of the page's previous content (mis-sized DN's
`les di,[bp+6]` to 2 bytes → corrupted IP/flow). Works on metal because a real
CPU guarantees store-vs-fetch coherence (I-cache snoop + serialization on the
overlay's far call). `flush_tlb` only did `ctl_flush_tlb` (softmmu TLB), never
`ctl_flush_tb` (translated code). Reconciles every prior failed lead — the
executed instruction *stream* was stale, so all the register/SP/null-ptr
"divergences" were downstream noise.
- [x] **Per-write TB invalidation (the fix).** `cpu::invalidate_code_range`
      (`ctl_remove_cache` per page — frames are scattered, so the range isn't
      physically contiguous) called from every `vcpu.rs` host-side write
      (`write`/`copy_to`/`zero`/`copy_within`). Restores x86 store-vs-fetch
      coherence at the one choke point, covering all code-load sources by
      construction. `invalidate_uc` also upgraded to drop TBs for its range
      (COW/remap frame-reuse: a recycled physical frame can carry a previous
      owner's TBs). Verified: DN launches digger, RTE-204 idle loop gone.
- [ ] **No-translation-cache CI mode (the "never again" net).** `RETRO_FLUSH_TB=1`
      already flushes ALL TBs at slice entry (`configure`), forcing re-decode of
      every instruction from current memory — staleness becomes structurally
      impossible. Wire a CI job that runs the DOS/game suite twice (cached vs
      `RETRO_FLUSH_TB`): **any** behavioral divergence is, by definition, a
      missing invalidation, caught the moment it's introduced. (No true Unicorn
      interpreter mode exists; per-slice/per-block flush is the equivalent.) This
      is the RIGHT regression layer — it exercises real RetroOS execution, unlike
      a standalone unicorn-decoder unit test (those were diagnosis, not RetroOS
      tests, and live on `debug/dn-launch-instruction-trace`).
- [ ] **Batch the invalidation (perf optimization).** Per-write `ctl_remove_cache`
      runs on every guest write incl. tiny BDA/stack pokes, and each does a
      `get_page_addr_code` softmmu walk. Instead, accumulate written
      `(space, page)` ranges in a thread-local dirty set during the kernel turn
      and drain them once at the next `configure` (slice entry) — where CR3 is
      freshly loaded for the space about to run, so `ctl_remove_cache` resolves
      against the correct page tables (also fixes the theoretical cross-space
      case the per-write version resolves against the *last* slice's CR3).
      Collapse to a single `ctl_flush_tb` when the dirty set is large.
- [ ] **Cleanup.** Strip the remaining ad-hoc launch-debug instrumentation in
      `arch-interp/src/{cpu.rs,vcpu.rs}` (INSN/ITREG/STRINT/WR* hooks, the
      `0x3db93` probes) and the metal `pm_step_log` SI/DI/BP additions, kept
      across the hunt. Keep `RETRO_FLUSH_TB` (now the diagnostic mode above).

---

## Mode X DONE; Doom slow = store ceiling, not the VGA path (measured 2026-06-12)
- [x] **Mode X / Mode Y plane aliasing WORKS** (2fab439, 9a58ca9, f57e96a):
      Doom renders its 3D view + status bar with page-flipping (CRTC start
      address). A0000 paged onto the active plane, renderer reads the planes,
      detection via explicit-unchain state, no per-write trap.
- [ ] **Doom slow, raptor fast — ROOT-CAUSED by perf profile (2026-06-13):
      per-page mem_map_ptr region blowup, NOT stores, NOT the block hook,
      NOT the VGA feeder.** User's logic ("raptor is fat too, can't be a
      per-store dirty thing affecting both") was right and decisive. perf on
      Doom: 75% self-time in qemu_ram_alloc_from_ptr (+ render_memory_region,
      memory_map_ptr); raptor: 0% there. The interp maps guest RAM ONE PAGE
      per mem_map_ptr in the MEM_UNMAPPED hook — each new page allocates a
      unicorn RAMBlock and rebuilds the flatview, O(regions) per map. Doom
      streams a large/growing working set (4MB WAD + level/texture data +
      256K Mode Y planes) → thousands of regions → O(n^2). raptor's small
      working set maps once and stabilizes → no churn. (Earlier wrong turns,
      for the record: block-hook/TB-chaining was a virtual-time ARTIFACT
      not real speedup; the store/dirty-bitmap theory is contradicted by
      raptor being fast.) THE FIX = stop the per-page region explosion: map
      guest memory in LARGER spans (commit + mem_map_ptr a chunk, e.g.
      64KB-1MB, per fault) so the RAMBlock/region count and per-map flatview
      cost collapse; or restructure to a single large region with host-
      mprotect + a SIGSEGV demand-paging handler (bigger, the "proper" QEMU-
      like topology). Verify region count drops and re-profile. CAREFUL: a
      chunk must handle partially-committed (sparse) and already-unicorn-
      mapped pages without overlap errors. Measure with perf / a real metric,
      NOT present-fps (it tracks virtual-time charging, not throughput).

## VGA: planar/Mode X VRAM trapping (renderer done be39c43; needs the feeder)
The shared renderer now draws CGA/EGA-planar/Mode X from a 4-plane model +
registers (lib::vga_render, unit-tested). What's missing is POPULATING the
planes: planar/unchained writes route a single CPU store to A0000 through the
GC (write modes 0-3, the 4 latches, SEQ plane mask, bit mask + ALU) into 1-4
planes — the result is NOT what lands in linear A0000 RAM, so it must be
modelled at WRITE time. The plane logic belongs in VgaState
(vram_write/vram_read, kernel-side, the one VGA model). Open DESIGN question
is the trap routing + where it runs:
- [ ] **Renderer + sync DONE** (be39c43, c1c2fce): model-complete renderer
      (CGA/EGA-planar/ModeX, register classify) + chain4 split/merge, all
      unit-tested. Remaining = the paging-alias feeder.
- [ ] **Design LOCKED (metal-native, user-directed):** planes + a 64K
      "chained view" are PHYSICAL frames; A0000 always aliases one linear
      64K — the chained view (mode 13h/text) or the active plane (ModeX) —
      via paging, so the CPU never traps. Sync (chain4_split/merge) runs
      only on the rare chain<->unchain hop. EGA multi-plane set/reset
      fan-out stays a #PF-trap fallback (later). Renderer reads chained
      view for 13h, planes for ModeX.
- [ ] **Both backends ready with EXISTING primitives — no new arch surface.**
      (phys_view was added then reverted: unnecessary.) The kernel reads
      VRAM the SAME way the ac97/nvme drivers read DMA buffers — map the
      frames into a kernel-readable window via map_phys_range (cf. ac97's
      DMA_WIN_VA = LOW_MEM_BASE + 0xC_0000) and read there. Plan:
      alloc_phys_contig the 80 plane+chained frames; map_phys_range them
      into a kernel VRAM window (read for rendering) AND map A0000's 16
      vpages onto the active plane's frames (guest writes); repoint A0000
      on SEQ chain-4 / plane-select; chain4 sync on the hop. Disabled on a
      backend that can't alias — no per-backend method needed.
- [x] **Interp phys-memory model: DONE (5ba0490)** — map_phys_range honors
      ppage via a sparse memfd; alloc_phys_contig works; aliasing unit-
      tested. The blocker below is cleared.
- [ ] (cleared) Interp BLOCKER: no physical-memory model. Its map_phys_range is a
      stub (ignores ppage → map_fresh anonymous), and there's no guest-phys
      namespace that both a guest A0000 mapping AND the kernel's plane-read
      share. To "emulate the paging," the interp needs a real guest-phys
      backing: a phys buffer that map_phys_range(vpage→ppage) aliases into
      the guest VA window (mem_map_ptr) and that the kernel reads by phys
      address. THIS IS THE SAME SUBSTRATE the kernel-write-alias / CoW items
      want — one foundation, three unlocks. Build it next, then the VGA
      paging-alias is small kernel wiring on top.
- [ ] (superseded) Today A0000-AFFFF is plain demand-committed RAM.
- [ ] **Routing options to decide:**
      (a) Kernel event per VRAM access — simplest, correct, but a kernel
          round-trip per byte; a full 64KB planar redraw at 20fps is ~1.3MB/s
          of trapped writes → likely too slow.
      (b) Arch-side shared plane model — give the interp mem hook a pointer to
          the active thread's VgaState plane buffer + GC/SEQ latch state so the
          ALU runs in-hook without a kernel round-trip. Fast, but punches a
          hole in the arch boundary (arch touching kernel VGA state) unless we
          define a narrow "VRAM accessor" arch primitive the kernel installs.
      (c) Metal mirror: on metal-with-card the real hardware does this; on
          UEFI-no-card metal we'd need the same trap via #PF on the A0000
          mapping. So whatever (b) looks like should be expressible on both
          backends below the arch boundary.
- [ ] Also needed for register-authoritative classification: the personality
      BIOS INT 10h AH=00 should PROGRAM the canonical CRTC/SEQ/GC/AC register
      set per mode (it currently only writes the BDA byte + DAC). Then
      classify() trusts registers for everything incl. post-BIOS Mode X, and
      the BDA fallback becomes belt-and-suspenders. Independent of trapping
      but pairs with it.
- [ ] Latch/read modelling: planar READS load the 4 latches (used by
      write-mode-1 copies and read-mode-1 colour-compare); the model needs
      both directions, not just writes.

## Interp real paging (branch interp-real-paging — LANDED, one follow-up)
STATUS 2026-06-12: the live wiring is done and working. unicorn runs CR0.PG=1
over ONE guest-physical region (the phys memfd), softmmu walks our page tables.
Verified: kernel boot, VM86/DOS (DN, SkyRoads render; in-OS TCC builds a
byte-identical COMMAND.COM), and DOS/4GW PM (Doom runs through init at full
interpreter speed — the per-page mem_map_ptr O(n^2) blowup is gone). Commits:
ad2a678 (vm86 paged proof), a31b9da (live wiring), b487e07 (fault ownership).
Key bring-up fixes: run_trampoline must clear EFLAGS.VM before the CR0 bootstrap
(entering from a prior VM86 slice otherwise stays in VM86 and the iretd never
switches); and with PG=1 + no guest IDT a demand #PF escalates to #DF (vec 8) —
the intr hook snapshots the FIRST fault's vector+CR2 so the interp owns paging
faults (the guest IDT must never see them).
REMAINING (not paging-architecture; a DPMI timing detail):
- [ ] Doom spins in a PM timer-wait loop (at 01DF:0063258F, softint=0, an
      apparent IRQ0 storm: ~1M timer IRQs per profile interval with no progress).
      Doom's INT 8 tick ISR isn't advancing its counter. Suspect virtual-time /
      timer-IRQ delivery to the PM client (cf. feedback_interp_virtual_time_full
      _retire — block-hook charges time per block; a tight PM spin may overcharge
      and storm IRQ0). Next: trace whether the kernel invokes Doom's PM IRQ0 ISR
      at all, or only counts the IRQ; check EOI/IF gating for PM IRQ delivery.

## Interp real paging (superseded plan below — kept for the wiring checklist)
Replaces the per-page mem_map_ptr region model (Doom O(n^2) flatview blowup,
perf-proven) with QEMU's topology: guest RAM = ONE region, kernel page tables
in guest RAM, CR3/CR0.PG set, unicorn softmmu walks them. Done so far:
- [x] Proof: unicorn walks page tables we build (non-identity translate).
- [x] Page-table primitives over the phys memfd: new_page_dir / map_page /
      unmap_page / translate, unit-tested (arch-interp/src/paging.rs).
- [x] Page-table primitives (map/unmap/translate), unit-tested.
- [x] Keystone integration: one region + paging + demand-fault + software walk
      all compose. Learned: unicorn surfaces a paging #PF as no-EIP-progress +
      CR2 (no intr hook, no IDT); after writing a PTE, flush TLB by re-writing
      CR3. (46e85b3)
- [x] Address-space ops layer: space_new/switch/map_fresh/map_phys/set_writable
      /unmap/translate/fork (eager copy), unit-tested (4 paging tests green).
REMAINING — the live wiring (all-or-nothing; the kernel boots under it or not):
- [ ] cpu.rs build(): map the memfd as ONE region (mem_map_ptr(0, PHYS_SIZE,
      frame_ptr(0))) instead of the per-page MEM_UNMAPPED hook.
- [ ] cpu.rs configure(): CR3 = space::active_pd()<<12, CR0.PG=1 (GDT already
      built by write_tables); drop the flat per-space base addressing.
- [ ] cpu.rs execute(): replace the MEM_UNMAPPED demand path with the #PF retry
      loop (no-EIP-progress + CR2 → demand-commit or deliver PageFault → flush
      CR3 → re-emu_start).
- [ ] calls.rs: route arch_map_low_mem / map_fresh_range / map_phys_range /
      set_page_flags / unmap_range / free_range / user_fork / user_clean /
      switch_to onto the space_* ops. RootPageTable(u32 id) stays.
- [ ] vcpu.rs mem()/copy_from/copy_to: translate the guest vaddr via
      space_translate() → phys::frame_ptr(paddr) (page-crossing aware). This is
      the per-access cost change — measure it.
- [ ] RISK: copy_entries / swap_entries (COW + A20/HMA shadow) — today they
      copy/swap host-page CONTENT; on real tables decide whether they stay
      content ops or become PTE ops. Check kernel callers (A20 gate, HMA).
- [ ] Demand model: keep the current permissive auto-zero-on-fault (interp
      commits any non-null page) vs deliver #PF to the kernel — pick the one
      that matches what the kernel expects; the kernel pre-maps via map_fresh.
- [ ] Switch over; run raptor/doom/dn/duke/keen + re-profile Doom (qemu_ram_
      alloc_from_ptr must vanish); then delete mmu.rs Space model + the phys
      alias path's invalidate churn.
NOTE: master keeps the working Space model until this branch lands.

# PRIORITY: Interp parity with metal

The hosted/interp backend must run DOS software at the same level as metal —
it is the out-of-box emulator (project goal) and the development vehicle.
Known gaps, roughly by leverage:
- [ ] **Planar / Mode X needs VRAM trapping** (memory:
      project_hosted_game_workflow): mode 13h works via direct writes +
      renderer; planar modes need the A0000 window trapped through the
      VgaState plane logic on the interp. Unlocks a whole class of games.
- [x] **FIXED: stores had NO fast path in unicorn — store-heavy phases
      crawled ~1000x** (root-caused + patched 2026-06-11 via raptor;
      toolchain/unicorn-store-fastpath.patch, applied to the unicorn_fork
      http_archive — upstream into the fork repo and bump the rev when
      convenient). TLB fill now consults the TB page table
      (uc_phys_page_has_tb) instead of the stubbed is_clean≡true, and
      uc_mem_hook_installed no longer counts *_UNMAPPED hooks. Verified:
      raptor's init storms through in seconds (was: wedged for minutes),
      DN/skyroads/monkey2/prince/keen4/in-OS-TCC all clean. Original
      diagnosis below for the record.
      "QEMU runs it fine, same interpreter" — true for the TCG core, false
      for the memory subsystem. Unicorn deleted QEMU's dirty-memory
      bitmap: `cpu_physical_memory_is_clean()` is stubbed to `return
      true` (qemu/include/exec/ram_addr.h:70), so EVERY TLB fill marks
      writable RAM `TLB_NOTDIRTY` and EVERY store takes
      `helper_*_stw_mmu → notdirty_write` (cputlb.c:1189). In there, per
      store: a flatview lookup (`uc->memory_mapping` =
      address_space_translate), and — because our unmapped hook maps
      pages `Prot::ALL` (cpu.rs:162) — `mr->perms & UC_PROT_EXEC` is
      always true, so ALSO `page_collection_lock` +
      `tb_invalidate_phys_page_fast` PER STORE. The escape hatch
      (`tlb_set_dirty` at the end of notdirty_write) is disabled for us:
      it's gated on `!uc_mem_hook_installed()` and our global 0..MAX
      MEM_UNMAPPED hook makes that true for every address. QEMU proper:
      one pre-mapped dirty RAMBlock, stores are inline TLB hits (~ns),
      notdirty only for genuinely-clean/code pages and the first write
      re-dirties. Our per-4K-page mem_map_ptr topology adds flatview
      rebuild + full TLB flush per fresh page and thousands of regions to
      search. Net: raptor's DOS/4GW init (tens of MB of clears/copies)
      advanced ~0.3 VIRTUAL seconds in 5 wall minutes (rdtsc/ticks are
      instruction-anchored) — zero prof lines, no display_tick, blank
      screen; "RUNS" was a false positive. Store-light real-mode games
      (skyroads, monkey2) tolerate it. Fix ladder (fork is ours, all in
      scope): (1) map data pages W^X — drop EXEC from the unmapped-hook
      mapping, promote to EXEC on fetch fault → kills the per-store
      tb_invalidate/page-lock immediately; (2) chunk/eager-map regions
      (e.g. 256KB spans) → cheap flatview lookups, no per-page
      rebuild+flush; (3) fork patch: restore a real DIRTY_MEMORY_CODE
      bitmap (or page-has-TBs test) so non-code stores regain the inline
      fast path — true QEMU-parity fix.
- [x] **FIXED: personality-BIOS IVT had 256 distinct stub addresses —
      DOS/4GW's free-vector scan never terminated** (raptor layer 2,
      2026-06-11). After the store fix, raptor spun forever in a 20-byte
      RM loop at 04e6:62e3: DOS/4GW discovers the BIOS dummy-handler
      address by scanning the IVT for an address appearing in TWO entries
      (any duplicate must be the shared dummy; "unhooked vector" tests
      then compare against it — real BIOSes point all unassigned vectors
      at one dummy, so duplicates abound; verified it claims no vector,
      just records the address). Our install gave every vector its own stub
      (STUB_SEG:n*2) → no duplicates → infinite scan, burning 100% of
      virtual time, so the 18.2Hz tick interrupted the same 7 instructions
      forever. Fix (bios.rs install): unserviced vectors share vector
      0xFF's stub cell, mirroring real-BIOS topology; dispatch and
      hooked-detection are offset-independent. DOS/4GW now prints its
      Rational Systems banner and proceeds.
- [x] **FIXED: raptor layer 3 / duke3d crash — PM CLI/STI #GP must be
      emulated by the host** (1bb17d2). A CPL-3 STI #GPs at IOPL<3 and a
      DPMI host emulates it against the virtual IF (CWSDPMI/HDPMI do);
      we dispatched the #GP to the client's exception handler instead.
      DOS/4GW's IRQ epilogue STIs on every timer tick, so the first
      delivery after sound init cascaded (client #GP handler -> INT FC
      -> crossed HC unwind -> wild fetch at (0xEA00<<16)|0x51D5). Pure
      backend parity gap: metal's #GP runs the sensitive-instruction
      monitor first (arch-metal monitor.rs emulates CLI/STI below the
      arch boundary — NOT related to the old IOPL=3 leak), while the
      interp's PM path had no monitor pass; the interp's exception path
      now emulates CLI/STI inline (c1639c7) — below the arch boundary
      on both backends, the kernel never sees Exception(13) for these. Follow-up worth checking: does the interp have metal's
      TF-step tracking for PM POPF/IRET silent IF-drops? If not, that
      may BE the "virtual IF stuck at 0" item below. Raptor now RENDERS GRAPHICS on the interp; duke3d
      1.3d shareware runs through DOS/4GW 1.97 init (silent exit left =
      synthetic DUKE3D.CFG values, run real SETUP.EXE). Bonus fixes en
      route: interp CPL-0 iretd trampoline made atomic (slice ending
      mid-switch leaked ring-0 state as user regs), HC push/pop ledger
      now permanent DOS_TRACE lines. The kernel SEGV report prints stale
      saved regs — still worth fixing (separate small item).
- [ ] **display_tick classifies mode from the BDA byte (0x449), not from
      VgaState registers** — ModeX games reprogram CRTC/sequencer directly
      and the BDA still says 0x13, so the renderer either rejects the mode
      or renders it wrong. Unrenderable modes now log register state once
      (vga.rs); the real fix is deriving the mode from misc/seq/gc/crtc.
- [x] **LIKELY FIXED: virtual IF stuck at 0 on hosted** (31c367b) — the
      interp had no counterpart to metal's TF-stepping for POPF/IRET
      silent IF-drops (Hexen-via-DOS32A class). Fix: PM clients enter
      the software CPU at IOPL=3, so CLI/STI/POPF/IRET manipulate the
      emulated IF natively — no faults, no stepping, no holes; safe
      because IN/OUT hooks fire regardless of IOPL and slices end by
      count. store_regs re-pins kernel-visible IOPL to 1. Hexen (the
      documented hang) now runs and renders on the interp. Keep an eye
      on the intermittent freezers (DN idle, settlers) for a while
      before closing the sprint entries below.
- [ ] **DPMI client IOPL=3 leak** (bug sprint below) — backstopped, not
      root-fixed.
- [ ] **Interp idle efficiency:** DN idle on hosted burns 50/50
      user/kernel in a softint polling storm (~1M softints/s through the
      BIOS stubs); metal idles at user≈93%. Not a correctness gap, but the
      out-of-box experience cooks a host core.
- [ ] **Per-game bug-sprint list below** — most entries are hosted/interp;
      retest each against current master (the reap fix + platform work may
      have moved several), then fix by class, not by game.
- [ ] COW fork (interp fork is a full copy — "M4"); fine for correctness,
      costs ~6MB/launch of copying.

## Interp MMU — kernel writes must not be bound by guest protections
- [ ] **Structural parity gap (class behind the fork_copy SEGV, ec48a4d):**
      on metal the kernel writes user pages through its own ring-1 view,
      where guest-RO doesn't bind it; on the interp, kernel-side writes
      (arch::mem()/GuestBytes) go through the SAME host mapping that
      enforces guest protections — any kernel write to a page already
      protected RO segfaults the HOST. fork_copy was the first instance
      (fixed in-place); the ELF loader survives only by write-then-protect
      ordering convention. Fix the class below the arch boundary: give the
      interp MMU a permanently-writable kernel alias of guest memory —
      memfd_create + a second mmap of the same backing (mirrors metal's
      kernel-view/user-view split exactly, and is the natural substrate
      for interp CoW/M4 later: shared frames need refcounted backing
      anyway). Note on unicorn API: uc_mem_write does bypass unicorn-level
      page perms, but our guest protections live in the HOST mprotect
      layer (mmu.rs), which unicorn cannot bypass either — so the fix is
      in mmu.rs, not a unicorn call swap; unicorn keeps reading/executing
      through the guest-view mapping unchanged. Then revisit fork_copy:
      with a kernel alias the populate-then-protect ordering cannot be
      wrong by construction.

## Linux-on-interp console (surfaced 2026-06-12 via shell.elf workflow)
- [x] **FIXED (ec48a4d): busybox killed the whole host on its first
      command** — fork_copy committed child pages at final protection
      before the memcpy, so the first read-only page (ELF .text) made the
      copy write to PROT_READ and SIGSEGV'd retroos-host. First-ever fork
      of a read-only page on the interp.
- [ ] **Linux console output bypasses the window.** On the emulated
      display (play/UEFI), Linux stdout goes to host stdout — running
      shell.elf from DN in the play window leaves the window frozen on
      DN's screen while busybox lives in the launching terminal. The
      single-VGA design wants Linux console writes rendered through
      vga::vga() text console -> display_tick -> present sink, same as
      metal-with-card renders them through the real text page. Same work
      item as de-cfg'ing linux/mod.rs save/restore_console_vga (stale
      "interp has no VGA" comment; emulated path should snapshot/restore
      the model instead of ports). Cosmetics in the same area: busybox
      'can't access tty; job control off', and ash's ESC[6n cursor query
      is never answered.

# DOS Game Compatibility — Bug Sprint

## Re-baseline 2026-06-11 (headless harness, current master)
Direct `--cmd GAMES/...` launches, 40s each, benign key pokes, prof-line
freeze detection (`at=0050:*` = BIOS-stub input wait = alive), text/PPM
screen capture. Harness limits: no mouse, blind pokes, no eyes on frames.
- **Class A — extender init dies executing low-mem garbage (VM86 panic at
  dos/mod.rs:550):** stunts (ST.COM → 0000:3180), omf-direct
  (FILE0001.EXE), pinball-illusions (known pMAX incompat). NOT a
  regression (pre-factoring kernel identical class). omf/stunts may be
  wrong entry exe — verify the real launcher chain before kernel work.
- **Class B — quick clean exit, error presumably printed to text screen
  (uncaptured):** monkey1, indy3-jones, epicpinball, AND offroad — which
  previously FROZE in the 0x3DA vblank loop and now exits instead
  (behavior changed; needs eyes). Next: rerun with high-cadence screen
  capture to read the exit messages, then fix by error class.
- **Class C — runs; needs interactive/visual verification:**
  raptor (WAS the named DPMI crash — now EXECUTES without crashing;
  blank screen ROOT-CAUSED as the store-storm slowdown, see parity item
  above: init crawls in unicorn's per-store TLB-miss slow path and the
  virtual clock starves display_tick — NOT the planar gap), settlers
  (launches; the mouse-click #GP needs mouse injection to retest),
  goldenaxe (key coverage), extr-pinball (keypress-panic NOT reproduced
  under pokes — possibly fixed), indy4-atlantis (alive in graphics;
  mouse known-missing), aladdin (runs; audio/garbage need eyes/ears),
  monkey2 (reaches graphics then exits — further than the documented
  text-mode R6003).
- Controls: skyroads + prince healthy (graphics, title/attract).


## Hosted/interp — DN panel-Enter wedges (ffbf family, ROOT IN SIGHT 2026-06-12)
User symptom: in retroos-play, launching a program from the DN PANEL with
Enter never works (DN's own COMMAND-LINE exec works fine; --cmd works).
Reproduced on the CARGO terminal host: panel-Enter DOES initiate (DN reads
C:\BOOT\DN\DN.ARH — likely absent from the bootfs, open shows no success
line — then does its pre-spawn mouse setup: INT 33 0007/0008/0003/000C
(install callback mask=FFFF handler=0502:1E44)/0001/000F-unsupported), and
then DN's function at 0502:21xx (PUSH BP; INT 33 AX=000F; POP BP; LEAVE;
RETF 4) returns into HMA garbage: cs=ffbf:05da/05ad, SP collapsed — the
restored BP was trampled. The user's duke3d-from-DN crash (vec09 +
delivered_at ffbf:...) and the old retired DN-launch crash are the same
family. Watchpoint evidence (one run): right after the 000F excursion,
DN's hooked IRQ-handler chain (cs=2eec/50d8/234d) executed ON DN'S OWN
STACK at SP≈0x403c-0x4042 — ABOVE the live frame — overwriting saved-BP +
far-return slots (e.g. `write ret-cs val=0x403e from 2eec:0x177`). The
kernel's reflect_int_to_real_mode is DESIGNED to run RM handlers on the
dedicated RM slab (rm_get_stack: 01F6:100A — and the healthy [oth] ledger
cycles confirm to_pm→to_rm→resume→resume balanced to None), so the open
question is which delivery path ran DN's handlers on the CLIENT stack at a
STALE depth: stale other_stack Some((3f4a,...)), the inline VM86 software-
INT reflection (cpu.rs reflect_vm86_inline pushes on CURRENT stack — by
design, but maybe a chained INT from a handler?), or the parked console-
read (pending_resume) interleave. NEXT: re-add the temp traces (this entry
documents them all) with a DYNAMIC watchpoint armed at the AX=000F
d33-frame moment covering [sp+6 .. sp+12] of the live frame, capture only
between 000F-return and the RETF, and identify the writer's delivery path.
Temp instrumentation used (all reverted, recreate as needed): [d33-frame]
dump in dos.rs int33 tail; [oth] transition traces at the 3 other_stack
assignments in mode_transitions.rs; uc MEM_WRITE watchpoint in cpu.rs
build(); KBD_TRACE=true; DOS_TRACE_RT=true. Repro driver: boot cargo
target/release/retroos-host with a WRITABLE image copy, stdin: 8s wait,
type "cd \GAMES\PRINCE" 0.15s/char, Enter, 2s, ESC[B, Enter, wait.
ALSO FOUND (separate bugs, file/fix independently):
- [x] BAZEL-native retroos-host wedged DN pre-UI: ROOT-CAUSED — it was
      the unicorn store-fastpath patch (Bazel-only; see retraction above).
      Unpatched Bazel host runs DN fully (panels, input). Build flags and
      bootfs delivery were innocent.
- [ ] DN.ARH (and the rest of DN's data set?) missing from the embedded
      bootfs — DN's archive-detection config; open fails silently. Decide:
      add to bootfs or accept.
- [ ] COMMAND.COM duplication: ext4 root carries a copy (BUILD.bazel
      _EXTRA_FILES, "DN EXECs COMSPEC=C:\COMMAND.COM from C:\") AND the
      bootfs carries one. User wants bootfs-only: point the master-env
      COMSPEC at C:\BOOT\COMMAND.COM and drop the root copy.
- [ ] retroos-play window: text mode renders 8x16 (640x400) unscaled —
      smaller than qemu/bochs/86box (9x16 = 720x400, usually 2x-scaled).
      Add integer scaling (and ideally the 9-dot column) in play/display.rs.

## Hosted/interp — DN launch crashes in the swap cycle (DPMI PM-IRQ delivery)
- [x] **Resource leak fixed (630c335) — the suspected driver:** reap() never
      freed anything (slot flipped Unused; zombie kept VgaState planes +
      screen snapshot + LDT until slot reuse) and interp address spaces were
      IMMORTAL (mmu registry never removed entries: 3GB reservation + 1.5MB
      bookkeeping leaked per fork). Now: arch destroy_space(root) at reap,
      reap(machine,·) drops personality + space, and the event loop reaps
      ALL zombies before returning (callers never inherit zombies). PRINCE
      launch/quit cycles: RSS flat. Remaining hosted growth during exec
      churn = Unicorn TB-cache fill (bounded) — backend concern.
- [x] **Re-verified post-fix (2026-06-11): the crash is gone.** Sweep of 5
      keystroke-timing variants (0.10–0.22s/char, including the documented
      0.15s pattern) x 3 PRINCE launch cycles each — 15 launch windows, all
      survived. Verdict: the resource leak was the driver. The
      locked-stack/IRQ-lane analysis below is RETIRED unless the panic
      (`unhandled opcode at ffbf:...`, `last_irq=vec08`) ever reappears —
      if it does, start from the analysis notes below.
- [ ] **Repro (deterministic per keystroke-timing pattern, headless):** boot
      image on retroos-host, type `cd \GAMES\PRINCE` (0.15s/char), Down,
      Enter → VM86 panic `unhandled opcode at ffbf:0433 (lin=0x100023)`,
      `last_irq=vec08 handler=0027:0510`. NOT a panel-vs-typed mechanism
      split: BOTH routes go through COMSPEC → our COMMAND.COM →
      SYNTH_FORK_EXEC (confirmed by F11 task switching working after panel
      launches on metal). DN wraps EVERY exec in its swap cycle — DN.PRG (a plain
      **real-mode** BP7 app: RM overlay runtime, NOT DPMI) exits, the
      dn.com stub runs the target, then re-EXECs DN.PRG — and the crash is
      a timer IRQ landing in a vulnerable window of that exec/return
      sequence (faulting delivery at
      cs=0502 = DN.PRG resident code during swap-out; same script minus the
      Enter survives 45s+). Instruction-anchored virtual time makes hit/miss
      deterministic for a given input-timing pattern — which is why some
      scripted runs survive the identical key sequence with different
      sleeps. Metal presumably wins by IRQ-phase luck OR handles the lane
      correctly; get a metal trace to tell which.
- [ ] **Established:** `0027:0510` is `pm_vectors[8]`'s DEFAULT entry —
      `VECTOR_STUB_SEL` (LDT idx 4) : stub slot 8 — NOT a client hook. So the
      crash is in the kernel's own default reflect lane: vec08 →
      `deliver_pm_irq` (guest mid-VM86-excursion) → vector stub `CD 31` →
      reflect toward the BIOS IVT handler, and the round trip comes back to
      VM86 with garbage CS=FFBF → wanders into the HMA window → `f0 25 ...`
      (LOCK AND reg) → unhandled-opcode panic. RM IVT[8] stays clean
      throughout (transition-sampled); in-process EXEC suspends/restores
      DPMI state correctly (dos.rs:2710). Same sequence works on metal/QEMU
      (DN game launches are routine there). Trigger window: immediately
      after DN.PRG's re-EXEC (exec_return restored the parent world, child
      freshly entered — first IRQ through the restored/new lane).
- [ ] **Suspects (narrowed 2026-06-09):** the IRQ lane is UNIVERSAL — every
      DOS thread's IRQ goes through deliver_pm_irq (mod.rs:826,
      unconditional): default vector ⇒ toggle to the PM-side locked stack +
      push HostContinuation, reflect to the RM IVT handler, pop HC to
      restore pre-IRQ segs. So plain RM DN rides locked_stack/other_stack/
      host_stack on every tick. exec_program suspends DPMI/pm_vectors/LDT/
      IVT (dos.rs:2710-2756) but does NOT touch dos.pc.locked_stack, and
      host_stack lives in shared low memory — prime suspect: excursion
      state (other_stack / HostContinuation slots) surviving across DN's
      swap-cycle EXEC/exec_return when it shouldn't (forward-edge sibling
      of the known exec_return locked-stack reset rule). Instrument
      locked_stack at EXEC/exec_return/delivery in the deterministic repro.
      Same failure family as the Settlers nested-callback #GP below.
- [ ] **Real gaps surfaced (fix regardless):**
      * Port 0x92 (fast A20) is unmodeled: reads return 0xFF = "A20 enabled"
        lie; writes drop. Model it (kbc/port92 → `set_a20`).
      * XMS AH=01/02 (Request/Release HMA) unimplemented → generic failure.
      * Interp `copy_entries`/`swap_entries` are CONTENT copies, not PTE
        aliases: the A20-off wrap "alias" of low memory is a stale snapshot
        on interp (wrap-detection through FFFF:xxxx sees frozen bytes), and
        HMA content does not survive A20 toggles the way metal's PTE swap
        does. Faithful A20/HMA needs real aliasing in the interp MMU.
- [ ] **Next:** rerun the deterministic repro with DOS_TRACE_RT armed at the
      2nd DN.PRG EXEC + PM single-step (`PM_STEP_BUDGET`) at the vec08
      delivery; dump the locked-stack/ModeSave chain; diff against a metal
      trace of the same panel-Enter sequence.

## Kernel — virtual IF gets stuck at 0
- Freezes seen for
      * Dos Navigator
      * Sokoban
      * Zone66
      * TIM
- [ ] Intermittent across games: a program runs fine for a while then
      freezes. F12 dump shows EFLAGS.IF=0 — some interrupt sequence
      (INT reflect / IRET / exception dispatch / mode transition) is
      leaving the user's virtual IF cleared and never restoring it.
      vPIC IRQs queue up but never get delivered, so anything waiting
      on a timer/keyboard IRQ wedges. Related to the Hexen hang above
      (same symptom, also IF=0 + VIP=1), but here it's not game-specific
      so the IF=1→0-without-pairing path is somewhere on a common code
      path, not Hexen-specific.

## Kernel — DPMI client IOPL=3 leak (backstopped, not root-fixed)
- [ ] **Find where the PM client's IOPL gets set to 3 and stop it at the
      source.** The system invariant is that *every* ring-3 guest runs at
      IOPL=1 (ring-1 kernel does port I/O directly; ring-3 traps closed ports
      through the TSS I/O bitmap into the raster emu / vPIC / vkbd). A PM/DPMI
      client that runs at IOPL=3 bypasses the bitmap entirely — 0x3DA, `out
      0x20`, `in 0x60` all go straight to the host — which broke the keyboard
      and wedged IRQs under Bochs (QEMU happened to tolerate it). This is now
      **backstopped** in the arch ring-3 exit (`traps.rs`, next to the IF/VIF
      normalization): IOPL is pinned to 1 on every exit, since it's a preserved
      flag the guest can't change anyway. That fixes the symptom, but the leak
      source is still unidentified — IOPL=3 was observed first appearing at the
      SPECIAL_STUB DPMI-entry stub (`003f:0x504`) on the VM86→PM return path.
      Leading suspect: with VME, a VM86 `PUSHF`/`INT` reports IOPL=3 in the
      pushed image regardless of the actual IOPL=1, and one of the cross-mode
      transitions that copy flags around (`raw_switch_real_to_pm`,
      `resume_continuation_from_stub`, `reflect_int_to_real_mode`) propagates
      that virtualized IOPL=3 into the PM client's real eflags. Track down which
      flag-copy is the culprit and mask IOPL there (or confirm the exit pin is
      the right single canonical point and document it as such). Reproduce by
      temporarily re-adding a `cs&3==3 && iopl!=1` panic in the event loop
      before `do_arch_execute` and running any DPMI game under Bochs.

## Prince of Persia
- [ ] **End-of-level door hangs, repeating.** When the prince reaches the exit
      door, the game wedges with the door animation/sound looping. Failure mode
      TBD — capture a trace at the level-exit transition (likely a wait loop on
      a timer/IRQ or sound-DMA completion that never fires).

## Ironman Off-Road Racing (Offroad)
- [ ] **Freezes / grinds to a halt — timer ISR's 0x3DA vblank loop never
      completes.** Root-caused (not yet fixed). The game installs an INT 8
      (timer) ISR at `067D:0A44` that re-tunes the PIT *phase-locked to vblank*
      by splitting the divisor write across a vblank edge, then JMP-FARs to the
      old handler:
      ```
        OUT 43h,36h
        MOV AX,[06BA]          ; new PIT divisor
        OUT 40h,AL             ; low byte only
        wait 0x3DA bit0 == 0   ; (out of blank)
        MOV CX,[06B8]          ; <-- the "reads-per-vblank" calibration count
      .lp:
        IN  AL,0x3DA           ; individual reads
        TEST AL,1
        LOOPNE .lp             ; count CX *sustained* bit0=1 reads
        JZ  restart            ; CX exhausted w/o vblank → retry
        OUT 40h,AL             ; high byte, now phase-locked to vblank
        ADD [06C1],1
        JMP FAR [06BD]
      ```
- [ ] **Why it hangs (solid):** the loop needs `CX = [06B8]` *consecutive*
      `bit0=1` reads to accept a vblank. Our synthetic 0x3DA (`synth_status1`,
      raster off `hr_cycles`) sustains bit0=1 for only ~565 consecutive
      *individual* `IN` reads, but `[06B8]` is **48963**. 48963 ≫ 565 → `LOOPNE`
      never falls through → ISR never returns → `[06C1]` (the game's frame
      counter) freezes → grind to a halt.
- [ ] **`[06B8]` is runtime-derived, not a shipped constant.** A gdb watchpoint
      on `[06B8]` (lin `0x8288`) caught its first write `0 → 48963` from
      F-segment block-I/O (`REP INSD`). 48963 reads/vblank implies a ~200+ MHz
      `IN`/`TEST`/`LOOPNE` throughput — impossible for the game's 1990 target, so
      the game *calibrated this count against our (fast) emulated read rate* and
      stored it. (Exact calibration instruction not pinned down — gdb's
      real-mode watchpoint disassembly kept erroring; the magnitude alone proves
      runtime derivation.)
- [ ] **The fundamental tension.** The whole 0x3DA scheme assumes
      reads-per-second is a fixed constant (one CPU speed): the game calibrates
      the count in one path and consumes it in the ISR via individual `IN`.
      Under a *trapping* emulator the per-read cost isn't constant — in
      particular a block `REP INS` (a strong candidate for the calibration path)
      and individual `IN` (the ISR) don't cost the same — so the calibrated
      count is structurally unreachable by the ISR. A *time-based* 0x3DA can
      never satisfy a read-count detector unless reads occur at the calibrated
      rate.
- [ ] **Fix options (undecided):**
      1. *Cheap, uniform 0x3DA reads* (fast in-trap path, or don't trap 0x3DA
         for the common read pattern) so reads track a near-constant rate and
         calibration ≈ ISR. Principled but the biggest change.
      2. *Read-count-based raster* (bit0 set for K reads, clear for M): fixes the
         hang but makes game speed depend on emulated read throughput and drifts
         against the time-based PIT. Earlier hblank/read-counter experiments were
         this, and failed only because K didn't match the calibrated count.
      3. Document as a known trap-based-VGA limitation and move on.

## Borland C IDE
- [ ] **Goal: successful WOLFSRC compile from the BC IDE** (`bc`, project
      `WOLF3D.PRJ`, sources served over hostfs at `C:\PROJECT\WOLFSRC`).
  - [ ] **Blocked: 2nd TASM exec under bc crashes #UD.** Build order now: C0.ASM
        (TASM #1) assembles ✓, TASM2MSG ✓, then H_LDIV.ASM (TASM #2) → CPU
        exception 6 at `f4a4:0x206c` (vm86) — a wild far transfer into the
        F-segment BIOS region; the crash stack holds ASCII string data, not a
        return addr (misplaced/corrupted stack). NOT file-specific: H_LDIV.ASM
        assembles `Error messages: None` standalone via `-r`. Both TASM execs
        load **identically** (child_seg=02DF, cs:ip=1B79:1AEE, psp=0BD9), so the
        corruption is resident state carried across the bc DPMI-host's
        EXEC/reap cycles — same family as `[[project_bcc_regression_is_flaky_layout]]`
        (the 14e7301 MCB-keep fix), evidently not fully closed. Clean execs
        restore bc to its PM stack (`ss:sp=0597:F572 pm_env=restored`); the
        crashing one degrades to a real-mode frame (`0239:013A`). Next:
        run the full bc compile with PM single-step / DOS_TRACE_RT armed at the
        2nd TASM EXEC; dump the locked-stack/mode-save chain + MCB list at
        child entry and diff vs the 1st (working) TASM exec.

## Settlers (DOS/4GW 32-bit)
- [ ] **Mouse click → kernel #GP panic.** NOT the BC selector-as-paragraph bug
      (that fix is correctly bypassed here). Settlers runs under **DOS/4GW 1.92**
      as a 32-bit DPMI client and does its **own** PM↔RM mouse bridging:
      - DOS/4GW hooks PM INT 33h (`015f:0xcc`) and, via `AX=0204`, captures the
        prior PM vector = our `SLOT_PMDOS_INT33` host stub (`003f:06f4` =
        `SPECIAL_STUB_SEL : STUB_BASE+0xFA*2`). For ordinary functions
        (AX=000E/0002/…) it **chains to our handler** → serviced in PM, works.
        (Confirms the `pm_vectors[0x33]` routing is load-bearing — keep it.)
      - For **AX=000C** it intercepts and reflects to real mode via **DPMI
        AX=0302** (call RM proc), passing its own **tiled** trampoline
        `ES:DX = 0229:0000` (DOS/4GW uses 1:1 selector tiling: base = sel<<4,
        so `0229` ↔ linear `0x2290`). So `int_33h` correctly sees VM86 →
        `cb_is_pm=false`; DOS/4GW *wants* a real-mode callback.
      - Failure: our RM far-call reaches `0229:0000` (trampoline runs), which
        switches RM→PM and raises **`INT 60h`** (DOS/4GW's internal gateway) to
        call the app's 32-bit handler. The panic is a kernel `#GP err=0x200` while
        **delivering that PM `INT 60h`** — the IRET-to-user (`common_call+0x39`)
        loads an invalid selector `0x200` on client `SS:ESP=002f:0x2094`. Trace:
        `[MOUSE] CB enter -> 0229:0 → [DPMI] PM_INT vec=60 -> 015f:0x180 → PANIC`.
      - **Root is a nested cross-mode transition during a mouse callback**
        (PM client → our RM-callback excursion → DOS/4GW RM trampoline →
        RM→PM → `INT 60h`), likely corrupting the locked-stack/`other_stack`
        chain or leaking a garbage segment that the PM-INT-60 IRET then loads.
      - Underlying hardening gap: a `#GP` from a bad client segment on the
        IRET-to-user path should be re-attributed to the client (vector 0x0D →
        DOS/4GW's installed exception handler), not panic the kernel as
        "Unhandled exception in arch" (`traps.rs:873`).
      - **Next:** arm PM single-step at `[MOUSE] CB enter`, trace the `0229:0000`
        trampoline through its RM→PM→`INT 60h` sequence, find where `0x200`
        enters and dump the locked-stack/mode-save chain at the `INT 60h`
        delivery vs. a clean PM-INT delivery. Headless `-r` repro won't reach
        a click; needs interactive + `DOS_TRACE_RT` (AH=02) on.

## Monkey Island 1, 2 — SCUMM
- [ ] Hits `run-time error R6003 - integer divide by 0` (#DE) just after
      entering mode 13h — the classic SCUMM fast-CPU timing calibration
      divide-by-zero (a measurement loop sees 0 timer-tick delta because the
      guest runs at full native host speed with no throttle). Same root
      cause as Indy 3's startup divide-by-0 below; fixing one should fix both.

## Indiana Jones IV: Fate of Atlantis (CD)
- [ ] **Mouse doesn't work** — no mouse clicks register; you have to drive
      menus/dialogue with Enter instead. The game now boots and runs (RTC
      wait + ext4 on-demand reads fixed the earlier hang/OOM). SCUMM runs in
      real mode (VM86), so unlike the BC IDE / Settlers cases this is *not*
      the PM-handler-as-RM-paragraph bug — likely the INT 33 button/callback
      path: either AX=0003 button state isn't reflecting presses, or the
      AX=000C event callback / AX=0005 press-count isn't delivered. Needs a
      trace of which INT 33 subfunctions SCUMM polls.

## Indiana Jones and the last crusade
- [ ] Division by 0 error on startup

## Epic Pinball
- [ ] Menu is way too fast, arrow keypresses often result in 2/3 steps

## One Must Fall 2097 (RESOLVED 2026-07-03)
- [x] (sb-dma-virt) MOD music has deep comb-echo "reverb" + unstable
      tempo at "ultra high quality" mixing; "486" mixing sounds normal.
      Not a buffer/remap-coherency bug (a coherency fault would echo at
      any rate). It's a throughput ceiling: with host IRQ5 re-armed on
      the guest vPIC EOI (`0x20`) — the correct, existing trigger — the
      full per-IRQ round trip (QEMU sb16 → host trap → event-loop drain
      → relay → vPIC → mode-transition into guest ISR → passthrough port
      I/O traps → EOI → cross-mode restore) exceeds the ultra-quality
      segment period, so free-running auto-init drops segments. Prime
      suspect: `run_qemu.sh` runs QEMU under TCG (no `-enable-kvm` /
      `-accel`), inflating every trap. Rejected dead-ends: auto-init
      special-case + kernel-side 2xEh ack (reverted — both hacks); the
      0x22E-read re-arm idea (wrong; EOI 0x20 is the right trigger).
- [x] Restart from launcher after quitting OMF hangs. **Diagnosis
      confirmed** via fresh trace: OMF2 enters a tight `INT 21 AH=2C`
      (GetTime) timeout loop that OMF1 never executes (526 calls vs 0)
      — different sound-init branch. EFLAGS in the loop: IF=0, VIP=1,
      vpic `pending=[08,0F,09]` (timer + SB IRQ + kbd queued, all
      blocked by IF=0). BIOS tick at `0:046C` therefore can't advance,
      AH=2C returns the same time forever, the timeout never fires.
      Root is *not* IF=0 itself (umbrella IF-stuck bug downstream) —
      it's persistent HW state (most likely SB DSP / real 8237 / host-
      IRQ5 mask) carried over from OMF1 sending OMF2 down a "wait for
      the card to settle" branch. Speculative fix: issue an SB DSP
      reset and mask the host SB channels in `release_dma_pool` so the
      next program sees a clean card.

## Aladdin
- [ ] Sound is bad and game after a bit starts producing garbage on screen

## GoldenAxe
- [ ] Keyboard is missing keys preventing from actually selecting
      a player and starting the game. You need awkward keyboard bindings
      in its keyboard config menu

## Pinball illusions
- [ ] pMAX protected mode is incompatible

## Extreme pinball (RESOLVED)
- [x] Kernel panic on keypress

## Strunts
- [ ] Does not start

# QEMU related problems

There are some known problems that also occur in regular QEMU+freedos 
emulation, which should match original hardware closest. These are
thus not related to RetroOS but due to inaccurate QEMU emulation.

## List

- Odd/even vga address mode problem
  * Keen4e signon screen is slightly garbled. QEMU EGA emulation is doing
    something wrong with odd/even addressing, causing the checkmarks to
    by located at wrong position and attribute bytes to garble part of
    screen.
  * Jazz Jackrabbit gameplay is garbled (old sprite/scroll positions not
    erased) on QEMU 8.2.2. Jazz uses an undocumented odd/even mode applied to
    256-color graphics (tweaked Mode X w/ double-buffer + VRAM wraparound).
    QEMU's maintainer fixed odd/even + VRAM-wraparound handling (patch
    2023-12-31, postdates the 8.2 branch) → expected fixed on QEMU ≥9.0.
    RetroOS is not in the pixel path (VGA passthrough); see the Jazz entry
    above. Bochs renders it but is too slow at realtime sync to finish loading.
- No hsync/vsync emulation in vga port 3da.
  * Wolf3d hangs
  * Epic pinball, supaplex and other games unplayable fast 
  RetroOS solves this explicitly by producing synthetic vtrace/htrace
- SB16 emulation problem
  * Dune2 stops digitized speech after first sample
