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
- [ ] Scheduler change: background threads keep executing while an
      unfocused DOS app renders into its own VgaState and gets no input.
      Everything keyed off `focus::focused()` is already in place; the event
      loop needs to multiplex Ready threads instead of parking on the
      focused one. Watch the DN swap-cycle DPMI bug (see bug sprint) — it
      lives in exactly this machinery.
- [ ] Route keyboard/mouse explicitly through `focus::focused()` instead of
      "whoever is running" (equivalent today, load-bearing after the
      scheduler change).

## 3. Better kernel init structure
`startup.rs` does too much inline — TAR/ext4 mounts, CONFIG.SYS, AC'97 probe,
hostfs, the cmdline/DN dispatch, the boot self-build — in one long function.
- [x] Restructured (ee9ab48): startup() is an ordered spine — heap →
      platform probe → threading → block → mount_filesystems →
      init_device_policy → load_master_env → init_console_pipe → run. Both
      entry points (metal enter_ring1, hosted main) share it.

## 4. Sound Blaster: passthrough vs emulation
Passthrough-vs-emulation is decided ad-hoc by `ensure_mode` probing, and the
OPL / DSP / mixer / 8237 handling is split across the two paths.
- [ ] A cleaner "real card vs emulated card" device abstraction spanning the
      AC'97 sink, OPL (detection now; **synth** for actual music later), the
      passthrough remap, and the DSP/mixer. See memories
      `project_dma_zero_copy_design`, `project_ac97_lowmem_dma_window_todo`.

## 5. Hosted: HDD image vs host filesystem
The hosted backend can boot a disk image (interpreted ATA) or mount a host dir
(hostfs over COM1); choosing/combining them is ad-hoc.
- [ ] A clean model: boot from a disk image **or** run a program straight from a
      host directory mounted as a drive (DOSBox-style `mount c .`), so you can
      drop DOS games in a host folder and run them with no image build.

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

## 7. Real-laptop boot reset after "Heap initialized" (ACTIVE HUNT)
The laptop resets silently right after the "Heap initialized" print — no
panic, no double-fault dump, machine just reboots. Same kernel boots fine on
QEMU UEFI, Bochs+OVMF (`run_uefi_bochs.sh`), and hosted. Eliminated so far:
port-0x80 side effects (delays removed entirely, still resets), and
"handler couldn't run" (an IST1 double-fault handler now prints+halts for
that whole class — yet the reset stays silent, so the machine dies without a
deliverable CPU fault: smells like a write to firmware/SMM-owned memory the
multiboot map called free, or something interrupt/time-driven).
- [ ] **Get the countdown verdict.** The instrumented kernel (local branch
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

---

# DOS Game Compatibility — Bug Sprint

## Hosted/interp — DN launch crashes in the swap cycle (DPMI PM-IRQ delivery)
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

## One Must Fall 2097
- [ ] (sb-dma-virt) MOD music has deep comb-echo "reverb" + unstable
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
- [ ] Restart from launcher after quitting OMF hangs. **Diagnosis
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

## Extreme pinball
- [ ] Kernel panic on keypress

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
