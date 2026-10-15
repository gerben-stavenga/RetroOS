//! DOS low-memory structures, PSP/JFT, interrupt stubs and system tables.

use crate::Regs;
use crate::kernel::thread;
use crate::kernel::dos::{dfs, xms};
use crate::kernel::dos::machine::write_u16;
use super::exec::ParentRef;

pub(super) fn psp_struct_seg<A: crate::Arch>(dos: &thread::DosState<A>) -> u16 {
    dos.current_psp
}

/// First handle AH=45h may hand out (0-2 are the std slots).
// /// Prepare the VM86 IVT for a new process.
// ///
// /// The BIOS IVT at 0x0000-0x03FF is preserved from the COW copy of page 0,
// /// so BIOS handlers in ROM (0xF0000-0xFFFFF) are accessible. When a BIOS
// /// handler does I/O (IN/OUT), it traps through the IOPB to our virtual
// /// PIC/keyboard, so BIOS code works transparently.
// ///
// ── Low-memory layout ────────────────────────────────────────────────
// Single struct at LOW_MEM_BASE so field offsets propagate automatically
// when sizes change. The fake DOS internal structures (PSP, LoL, SFT, CDS)
// are typed sub-structs; the stub array and IRQ stack are byte arrays.
// `heap_start()` returns the first free paragraph past this layout — the
// initial DOS program's env arena lives there, with its PSP at +0x10.

pub(super) const LOW_MEM_BASE: u32 = 0x500;
const NUM_DRIVES: u8 = 12;
const SFT_ENTRIES: usize = 20;

/// Entries in the PSP's inline Job File Table. AH=67h can replace it with an
/// allocated external table and update PSP:34h to point there.
pub(crate) const PSP_JFT_LEN: usize = 20;

/// A handle with no slot in the process's active Job File Table.
///
/// A caller that has just opened, created or duplicated a file must treat this
/// as fatal for that handle: DOS has nowhere to record it, so as far as the
/// program is concerned the handle cannot exist, and the call has to come back
/// as error 4 ("too many open files"). Real DOS answers that once the table is
/// full, and a client that gets it closes something and retries.
///
/// Handing the handle out anyway and merely declining to record it is what
/// broke Dark Forces after Duke3D: DOS/4GW holds ~16 concurrent opens of the
/// .EXE while scanning it, which just fits under 20 from a clean shell.
/// Launched from DN after a child has run, DN is still holding DN.OVR and
/// DN.DLG, the inherited JFT starts two slots higher, the scan ran off the end
/// of the table, and DOS/4GW — never told to back off — bailed to its error
/// handler instead.
#[derive(Debug, Clone, Copy)]
pub(crate) struct JftFull;

/// Program Segment Prefix (DOS 3+, 256 bytes). Only the fields we read or
/// write are named; the rest is reserved padding so byte offsets stay stable
/// for any guest code that walks the structure directly.
///
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(in crate::kernel::dos) struct Psp {
    pub int_20:           [u8; 2],   // 0x00 — CD 20 (terminate)
    pub top_of_mem:       u16,        // 0x02 — segment past program (paragraphs)
    pub(super) _reserved_04:         u8,         // 0x04
    pub(super) _cpm_call:            [u8; 5],    // 0x05 — far call to CP/M dispatcher
    pub(super) _terminate_addr:      u32,        // 0x0A — INT 22h vector
    pub(super) _ctrl_break_addr:     u32,        // 0x0E — INT 23h vector
    pub(super) _critical_err:        u32,        // 0x12 — INT 24h vector
    pub parent_psp:       u16,        // 0x16 — parent PSP segment
    pub jft:              [u8; 20],   // 0x18 — inline Job File Table
    pub env_seg:          u16,        // 0x2C — environment segment (or 0)
    pub(super) _ss_sp:               u32,        // 0x2E — SS:SP at last INT 21
    pub max_files:        u16,        // 0x32 — JFT size
    pub jft_far_off:      u16,        // 0x34 — far ptr to active JFT
    pub jft_far_seg:      u16,        // 0x36
    pub(super) _reserved_38:         [u8; 0x80 - 0x38], // 0x38-0x7F
    pub cmdline_len:      u8,         // 0x80
    pub cmdline:          [u8; 127],  // 0x81-0xFF (CR-terminated)
}
const _: () = assert!(core::mem::size_of::<Psp>() == 256);
impl Psp {
    /// Linear base of the 256-byte PSP at `psp_seg` (`[psp_seg<<4 ..]`).
    #[inline]
    pub(super) fn base(psp_seg: u16) -> usize { ((psp_seg as u32) << 4) as usize }
    /// Write the whole PSP at `psp_seg`.
    pub fn store<A: crate::Arch>(machine: &mut A, psp_seg: u16, psp: Self) { machine.write::<Self>(Self::base(psp_seg), psp); }
    /// Read PSP[0x2C] (environment segment or selector).
    pub fn env_seg<A: crate::Arch>(machine: &mut A, psp_seg: u16) -> u16 {
        machine.read::<u16>(Self::base(psp_seg) + core::mem::offset_of!(Self, env_seg))
    }
    /// Linear address of the process's active Job File Table.
    pub fn jft_addr<A: crate::Arch>(machine: &mut A, psp_seg: u16) -> usize {
        let base = Self::base(psp_seg);
        let off = machine.read::<u16>(base + core::mem::offset_of!(Self, jft_far_off)) as usize;
        let seg = machine.read::<u16>(base + core::mem::offset_of!(Self, jft_far_seg)) as usize;
        (seg << 4) + off
    }

    /// Current capacity of the active JFT.
    pub fn max_files<A: crate::Arch>(machine: &mut A, psp_seg: u16) -> u16 {
        machine.read::<u16>(Self::base(psp_seg) + core::mem::offset_of!(Self, max_files))
    }

    /// Segment of an AH=67h-allocated JFT, if the inline table is not active.
    pub fn external_jft_seg<A: crate::Arch>(machine: &mut A, psp_seg: u16) -> Option<u16> {
        let base = Self::base(psp_seg);
        let off = machine.read::<u16>(base + core::mem::offset_of!(Self, jft_far_off));
        let seg = machine.read::<u16>(base + core::mem::offset_of!(Self, jft_far_seg));
        if off == 0x0018 && seg == psp_seg { None } else { Some(seg) }
    }

    /// Select a new active JFT and publish its capacity in the PSP.
    pub fn set_jft_location<A: crate::Arch>(machine: &mut A, psp_seg: u16, count: u16, off: u16, seg: u16) {
        let base = Self::base(psp_seg);
        machine.write::<u16>(base + core::mem::offset_of!(Self, max_files), count);
        machine.write::<u16>(base + core::mem::offset_of!(Self, jft_far_off), off);
        machine.write::<u16>(base + core::mem::offset_of!(Self, jft_far_seg), seg);
    }

    /// Record one entry in the process's active Job File Table.
    ///
    /// `Err(JftFull)` when the handle has no slot in the table. This is the one
    /// place the active table's bound is checked, so callers that are recording
    /// a handle must deal with a handle DOS cannot represent.
    pub fn set_jft<A: crate::Arch>(machine: &mut A, psp_seg: u16, idx: usize, val: u8)
        -> Result<(), JftFull>
    {
        if idx >= Self::max_files(machine, psp_seg) as usize { return Err(JftFull); }
        let addr = Self::jft_addr(machine, psp_seg) + idx;
        machine.write::<u8>(addr, val);
        Ok(())
    }

    /// Release one Job File Table slot.
    ///
    /// Unlike recording a handle, this genuinely may address a slot the table
    /// does not have, and that is not an error: DOS lets a program close the
    /// std handles and our out-of-band `NULL_FILE_HANDLE` / `EMS_DEVICE_HANDLE`
    /// (98/99), which by construction live outside the JFT. There is nothing to
    /// clear, so the write is skipped and the close still succeeds.
    pub fn clear_jft<A: crate::Arch>(machine: &mut A, psp_seg: u16, idx: usize) {
        let _ = Self::set_jft(machine, psp_seg, idx, 0xFF);
    }
    /// Install a command-tail at PSP[0x80] (length byte + bytes + CR).
    pub fn set_cmdline<A: crate::Arch>(machine: &mut A, psp_seg: u16, tail: &[u8]) {
        let n = tail.len().min(126);
        let base = Self::base(psp_seg);
        machine.write::<u8>(base + core::mem::offset_of!(Self, cmdline_len), n as u8);
        let cmd = base + core::mem::offset_of!(Self, cmdline);
        machine.copy_to(cmd, &tail[..n]);
        machine.write::<u8>(cmd + n, 0x0D);
    }
}
impl Default for Psp {
    fn default() -> Self { unsafe { core::mem::zeroed() } }
}

/// One System File Table entry (DOS 3+ format, 59 bytes).
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct SftEntry {
    refcount: u16,        // 0x00
    open_mode: u16,       // 0x02
    attribute: u8,        // 0x04
    device_info: u16,     // 0x05
    _reserved_07: [u8; 6],// 0x07
    time: u16,            // 0x0D
    date: u16,            // 0x0F
    size: u32,            // 0x11
    position: u32,        // 0x15
    _trailer: [u8; 34],   // 0x19-0x3A (filename + DOS-internal fields we don't fill)
}
const _: () = assert!(core::mem::size_of::<SftEntry>() == 59);
impl Default for SftEntry {
    fn default() -> Self { unsafe { core::mem::zeroed() } }
}

/// SFT header followed by the entry array. Total 1186 bytes.
#[repr(C, packed)]
#[derive(Clone, Copy, Default)]
struct Sft {
    next: u32,                       // 0x00 — far ptr to next SFT block (FFFF:FFFF = end)
    count: u16,                      // 0x04
    entries: [SftEntry; SFT_ENTRIES],
}

/// List-of-Lists (DOS internal). Only the fields we actually fill are named;
/// the rest is reserved padding.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(super) struct Lol {
    _reserved_00: [u8; 4],
    sft_off: u16,                    // 0x04 — far ptr to SFT (off, seg)
    sft_seg: u16,
    _reserved_08: [u8; 14],
    cds_off: u16,                    // 0x16 — far ptr to CDS array
    cds_seg: u16,
    _reserved_1a: [u8; 6],
    block_devs: u8,                  // 0x20
    last_drive: u8,                  // 0x21
    _trailer: [u8; 30],
}
const _: () = assert!(core::mem::size_of::<Lol>() == 0x40);
impl Default for Lol {
    fn default() -> Self { unsafe { core::mem::zeroed() } }
}

/// Current Directory Structure (one per drive letter, DOS 3.3 format).
#[repr(C, packed)]
#[derive(Clone, Copy)]
struct CdsEntry {
    path: [u8; 67],                  // 0x00 — ASCIIZ (e.g. "C:\")
    flags: u16,                      // 0x43 — 0x4000 = valid physical drive
    _reserved_45: [u8; 10],
    backslash_off: u16,              // 0x4F — offset of '\' in `path`
}
const _: () = assert!(core::mem::size_of::<CdsEntry>() == 81);
impl Default for CdsEntry {
    fn default() -> Self { unsafe { core::mem::zeroed() } }
}

/// DOS block-device header published through MSCDEX AX=1501h.
///
/// The strategy and interrupt offsets name a shared RETF stub in the same
/// segment. CD-specific requests will eventually use AX=1510h; keeping these
/// entry points valid prevents software which inspects the driver chain from
/// finding a dangling header meanwhile.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(super) struct CdromDeviceHeader {
    next: u32,
    attributes: u16,
    strategy: u16,
    interrupt: u16,
    name: [u8; 8],
    reserved: u16,
    drive_letter: u8,
    subunits: u8,
}
const _: () = assert!(core::mem::size_of::<CdromDeviceHeader>() == 22);

/// Fixed kernel-owned region in conventional memory.
///
/// The CD 31 stub array, the *system program* (a Program — env + PSP — that
/// stands in for COMMAND.COM; its env carries the master COMSPEC/PATH, its
/// PSP self-references to terminate the parent chain), the LoL → SFT chain
/// DJGPP's fstat walks, the CDS array some programs read, and a private
/// IRQ-reflect stack so BIOS handlers don't trample the user's stack.
#[repr(C, packed)]
pub(super) struct LowMem {
    stubs:     [[u8; 2]; 256],        // 0x500
    /// Bootstrap sentinel PSP. Acts as the parent_psp / chain terminator
    /// for the very first program loaded (and as a fixed segment we hand
    /// out as a parent reference for cross-AS fork+exec where the actual
    /// parent's PSP isn't reachable). Real DOS keeps an analogous internal
    /// PSP in its resident kernel data — it lives below `heap_start` and
    /// is *not* part of the MCB chain.
    pub(super) boot_psp:  Psp,                    // 0x700: 256 bytes
    /// First MCB seg in the DOS memory chain. Real DOS stores this at
    /// `[LOL - 2]` (one WORD before the List of Lists structure). Programs
    /// (DOS/4G stubs, MEM utilities, etc.) call AH=52h to get the LOL
    /// pointer and then read the WORD just below it to find the chain
    /// head. `sync_mcb_chain` writes the current `dos.heap_base_seg` here
    /// every time the chain is updated.
    first_mcb_seg: u16,
    pub(super) lol:       Lol,                    // 0x902
    sft:       Sft,
    cds:       [CdsEntry; NUM_DRIVES as usize],
    pub(super) cdrom_header: CdromDeviceHeader,
    cdrom_retf: u8,
    /// Diskette drive parameter table. IVT vector 1Eh points here (a real
    /// BIOS convention DOS-era code follows to tune step/settle times), and
    /// INT 13h AH=08h returns it in ES:DI.
    pub(super) ddpt: [u8; 11],
    /// DPMI 0.9 §3.1.2 locked PM stack (referred to as "host_stack" in
    /// the implementation). 4 KB host-provided buffer used for HW IRQ /
    /// exception / RM-callback handling in PM. Switched onto on the
    /// first reflection to PM and switched away from on outermost
    /// return. Two aliasing LDT selectors (PM16 with B=0, PM32 with
    /// B=1) point at this same buffer so SP values are portable across
    /// client bitness.
    host_stack: [u8; HOST_STACK_SIZE],

    /// Dedicated RM stack — host-provided buffer used by all kernel-
    /// orchestrated RM execution (BIOS reflection from PM, DPMI
    /// 0300/0301/0302 PM->RM calls, RM-side of callbacks). Reused per-thread
    /// across excursions and shared LIFO via `other_stack` (no snapshot copy).
    ///
    /// MUST be large enough for a real-mode interrupt handler's full stack
    /// frame. DPMI 0.9 §3.1.3's 200H is only the *client*-supplied minimum;
    /// the *host*-provided stack for ss=0 sim-INT / BIOS calls must hold the
    /// handler itself. At 200H it overflowed: the Bochs VGA BIOS's VESA
    /// `INT 10h/4F00` handler ran a few bytes past the buffer, and because
    /// `host_stack` (holding the live HostContinuation) sits immediately below
    /// this buffer, the overflow clobbered the HC's segment slots → a garbage
    /// paragraph got popped as a selector on the PM exit → kernel #GP, hanging
    /// every DPMI app under Bochs (whose VGA BIOS is stack-hungrier than
    /// QEMU's SeaBIOS). 4 KB matches what real DPMI extenders provide and
    /// leaves ample headroom, incl. LIFO-nested excursions. Paragraph-aligned
    /// because `host_stack` precedes it and is a multiple of 16 in size.
    rm_stack: [u8; RM_STACK_SIZE],

    /// The video BIOS "static functionality table" (16 bytes) that INT 10h
    /// AH=1Bh points its caller at. On a real machine this lives in the video
    /// ROM; the substitute BIOS has no ROM, so it lives here — it must be at a
    /// *fixed guest-readable address*, because AH=1Bh hands out a far pointer
    /// the guest dereferences long after the call.
    video_static_info: [u8; 16],

    /// Stable VBE `VideoModePtr` target. A caller commonly reuses its 4F00h
    /// controller-info buffer for each 4F01h mode-info query while it walks
    /// this list, so the list cannot live inside the caller's output buffer.
    vbe_mode_list: [u16; VBE_MODE_LIST_CAPACITY],

    /// Guest-readable copies of the standard VGA ROM fonts. The substitute
    /// BIOS publishes these through INT 10h AX=1130h and points INT 43h at the
    /// font selected by the current mode. The low half of 8x8 is additionally
    /// mirrored at IBM's hardcoded `F000:FA6E` address for old software which
    /// bypasses both interfaces.
    font_8x8: [u8; 256 * 8],
    font_8x14: [u8; 256 * 14],
    font_8x16: [u8; 256 * 16],
}
const _: () = assert!(LOW_MEM_BASE as usize + core::mem::size_of::<LowMem>() <= 0x1_0000);

/// Locked PM stack size (see `LowMem::host_stack`).
const HOST_STACK_SIZE: usize = 4096;

/// The locked PM stack is split in two:
///
///   [EXC_STACK_TOP .. HOST_STACK_SIZE]  rm-call / IRQ continuation chain,
///                                       growing down from `host_stack_empty_sp()`
///   [0 .. EXC_STACK_TOP]                exception-dispatch region
///
/// Exception dispatch must NEVER park its frames on the client's own stack:
/// per DPMI 0.9 the handler runs on a host-provided locked stack, and a
/// fixup-style handler (DOS/4GW) legitimately builds its resume IRET frame
/// at `fault_esp - 12` — i.e. right inside anything the host put directly
/// below the faulting ESP. So each dispatch gets a fixed slot here indexed
/// by the current exception nesting depth.
pub(in crate::kernel::dos) const EXC_STACK_TOP: u32 = 2048;
/// Per-nesting-level slot span in the exception region: 126 bytes of
/// host frames (HostContinuation + RetF + 0.9 + 1.0 frames) plus handler
/// scratch. Depth is capped at EXC_STACK_TOP / EXC_STACK_SLOT levels.
pub(in crate::kernel::dos) const EXC_STACK_SLOT: u32 = 1024;
/// Dedicated RM stack size (see `LowMem::rm_stack`).
const RM_STACK_SIZE: usize = 0x1000;
pub(in crate::kernel::dos) const VBE_MODE_LIST_CAPACITY: usize = 512;

/// Linear address of a `LowMem` field, e.g. `lm_field(offset_of!(LowMem, lol))`.
/// The kernel-owned low-mem area is a *projection* written into guest memory
/// field-by-field through the vcpu — never borrowed as a Rust struct (it sits at
/// a fixed low address the guest can also reach).
#[inline]
fn lm_field(field_off: usize) -> usize { LOW_MEM_BASE as usize + field_off }

/// Update the chain-head pointer that lives at `[LOL - 2]`. Called from
/// `sync_mcb_chain` so AH=52h-style chain walkers see the current
/// `heap_base_seg`.
pub(in crate::kernel::dos) fn set_first_mcb_seg<A: crate::Arch>(machine: &mut A, seg: u16) {
    machine.write::<u16>(lm_field(core::mem::offset_of!(LowMem, first_mcb_seg)), seg);
}

/// Linear addresses of the substitute BIOS's guest-readable ROM-font copies.
pub(in crate::kernel::dos) fn font_8x8_addr() -> u32 {
    LOW_MEM_BASE + core::mem::offset_of!(LowMem, font_8x8) as u32
}

pub(in crate::kernel::dos) fn font_8x14_addr() -> u32 {
    LOW_MEM_BASE + core::mem::offset_of!(LowMem, font_8x14) as u32
}

pub(in crate::kernel::dos) fn font_8x16_addr() -> u32 {
    LOW_MEM_BASE + core::mem::offset_of!(LowMem, font_8x16) as u32
}

/// Linear address of the video static functionality table (see
/// `LowMem::video_static_info`); the substitute BIOS seeds it and INT 10h
/// AH=1Bh publishes it as a far pointer.
pub(in crate::kernel::dos) fn video_static_info_addr() -> u32 {
    LOW_MEM_BASE + core::mem::offset_of!(LowMem, video_static_info) as u32
}

/// Linear address published as VBE ControllerInfo.VideoModePtr. LowMem stays
/// below 64 KiB, so segment zero plus this offset is a valid real-mode far
/// pointer.
pub(in crate::kernel::dos) fn vbe_mode_list_addr() -> u32 {
    let address = LOW_MEM_BASE + core::mem::offset_of!(LowMem, vbe_mode_list) as u32;
    debug_assert!(address + (VBE_MODE_LIST_CAPACITY * 2) as u32 <= 0x1_0000);
    address
}

pub(crate) const STUB_BASE: u32 = LOW_MEM_BASE;
pub(crate) const STUB_SEG: u16 = (LOW_MEM_BASE >> 4) as u16;

/// RM alias segment for the CONTROL view of the stub array. The ONE 256-slot
/// `CD 31` array serves two namespaces, separated purely by how its bytes are
/// addressed — the RM twin of PM's `SPECIAL_STUB_SEL` vs `VECTOR_STUB_SEL`
/// selectors aliasing the same array:
///
///   vector view:  `STUB_SEG:vector*2`             — IVT entries; slot == INT
///                 vector for all 256 (kernel-DOS redirects and the
///                 personality BIOS alike)
///   control view: `CTRL_STUB_SEG:STUB_BASE+slot*2` — far-call entry points
///                 the kernel hands out (XMS, DPMI entry, RM callbacks,
///                 resume/continuation parks)
///
/// Same bytes, same trap; CS alone says which namespace, so control-slot
/// numbering can never collide with vector numbering. CTRL_STUB_SEG = 0 makes
/// the control-view offset equal the linear address — the same arithmetic the
/// PM stub selectors use (their base is 0 too), so PM and RM control
/// addresses differ only in the segment/selector half. Segment 0 is never a
/// program's code segment, so the CS discrimination in `syscall` is
/// unambiguous.
pub(crate) const CTRL_STUB_SEG: u16 = 0x0000;

/// Control-view IP for a slot (= the linear address of its stub bytes).
pub(crate) const fn ctrl_slot_off(slot: u8) -> u16 {
    STUB_BASE as u16 + slot_offset(slot)
}
/// Offset within SYSPSP of the INDOS flag byte (permanently zero).
/// Placed in the "command tail" area since the system PSP never runs.
pub(super) const INDOS_FLAG_OFFSET: u16 = 0xFE;

/// First free paragraph past the kernel-owned low-mem area. The initial
/// DOS program's env arena lives here; its PSP at +0x10.
pub(in crate::kernel::dos) fn heap_start() -> u16 {
    let end = LOW_MEM_BASE as usize + core::mem::size_of::<LowMem>();
    ((end + 15) >> 4) as u16
}

pub(in crate::kernel::dos) fn boot_psp_seg() -> u16 {
    ((LOW_MEM_BASE + core::mem::offset_of!(LowMem, boot_psp) as u32) >> 4) as u16
}
/// Bootstrap parent reference for the initial program load. The env is the
/// kernel's compiled-in `MASTER_ENV` (no allocation needed); the parent
/// PSP is the boot sentinel.
pub(in crate::kernel::dos) fn boot_parent_with_env<'a>(env: &'a [u8]) -> ParentRef<'a> {
    ParentRef { psp_seg: boot_psp_seg(), env }
}

/// Base linear address + size of the kernel-shared host stack, consumed
/// by dpmi when building the three aliasing LDT selectors (PM16, PM32,
/// VM86 paragraph) that all point at this same buffer.
pub(in crate::kernel::dos) fn host_stack_base() -> u32 {
    LOW_MEM_BASE + core::mem::offset_of!(LowMem, host_stack) as u32
}
pub(in crate::kernel::dos) fn host_stack_size() -> u32 {
    HOST_STACK_SIZE as u32
}
/// SP value within `HOST_STACK_PM*_SEL` for an empty locked stack. The
/// selectors have base = host_stack_base() and limit = size−1, so the
/// post-init SP that pushes decrement from is exactly `size`. Used by
/// the transition layer as the chain-empty PM default.
pub(in crate::kernel::dos) fn host_stack_empty_sp() -> u32 {
    host_stack_size()
}

/// Base linear address + size of the per-thread dedicated RM stack.
/// `rm_stack_seg()` returns the paragraph floor of the buffer's base;
/// callers must add `(base & 0xF)` to any in-segment offset they pass
/// to BIOS as SP, to compensate for any sub-paragraph alignment of
/// the buffer's start within the LowMem layout. `mode_transitions::rm_stack_top`
/// does this for the standard "fresh-excursion top of stack" SP.
pub(in crate::kernel::dos) fn rm_stack_base() -> u32 {
    LOW_MEM_BASE + core::mem::offset_of!(LowMem, rm_stack) as u32
}
pub(in crate::kernel::dos) fn rm_stack_size() -> u32 {
    RM_STACK_SIZE as u32
}
pub(in crate::kernel::dos) fn rm_stack_seg() -> u16 {
    (rm_stack_base() >> 4) as u16
}
/// Sub-paragraph offset of the buffer's base within `rm_stack_seg()`.
/// `rm_stack_seg() << 4 + rm_stack_align_offset()` == `rm_stack_base()`.
pub(in crate::kernel::dos) fn rm_stack_align_offset() -> u16 {
    (rm_stack_base() & 0xF) as u16
}

/// Default size of an env block in paragraphs. Env is allocated from the
/// MCB chain like any other AH=48 block — its size is decided at alloc
/// time, not baked into a static struct.
pub(in crate::kernel::dos) const ENV_PARAS: u16 = 32;       // = 512 bytes (DOS5 typical /E:512)

// ── Stub vector / slot assignments ─────────────────────────────────────
// Slot N at offset N*2 from STUB_SEG. After CD 31, IP = N*2+2, slot = (IP-2)/2.
// VM86 traps via TSS bitmap bit 31h; PM fires INT 31h directly (DPL=3).
pub(in crate::kernel::dos) const STUB_INT: u8 = 0x31;
pub(super) const SLOT_XMS: u8 = 0x00;
pub(super) const SLOT_DPMI_ENTRY: u8 = 0x01;
pub(crate) const SLOT_RAW_REAL_TO_PM: u8 = 0x03;
pub(crate) const SLOT_CB_ENTRY_BASE: u8 = 0x04;
// Exclusive end. Stops at 0x13 because slot 0x13 collides with INT 13h
// (disk service) — the callback range MUST NOT shadow any IVT-redirected
// INT vector (INT 0x13 / 0x20 / 0x21 / 0x25 / 0x26 / 0x28 / 0x2E / 0x2F /
// 0x67). 15 callbacks at slots 0x04..0x12.
pub(crate) const SLOT_CB_ENTRY_END: u8 = 0x13;
// Inclusive last callback slot (== SLOT_CB_ENTRY_END - 1); used for the match
// range so it reads as `0x04..=0x12` rather than an exclusive end one short of
// the separate `SLOT_MOUSE_CB_RET`.
pub(crate) const SLOT_CB_ENTRY_LAST: u8 = SLOT_CB_ENTRY_END - 1;
/// Handler RETFs to this slot. `mouse_callback_return` restores the
/// bracket-saved GP regs (HostContinuation doesn't cover them) and then
/// unwinds the INT 33h callback via the standard continuation path.
pub(crate) const SLOT_MOUSE_CB_RET: u8 = 0x14;
/// VBE ModeInfoBlock.WinFuncPtr. This is RetroOS code, not a firmware pointer:
/// the far-call convention is Function 05h's BX/DX register ABI, while the
/// control-slot dispatcher routes the operation to the current process VGA.
pub(crate) const SLOT_VBE_WINDOW: u8 = 0x15;
/// Return point for the INT 15h/AH=4Fh hook invoked by BIOS INT 9.
pub(crate) const SLOT_KBD_INTERCEPT_RETURN: u8 = 0x16;
/// INT 21h/AH=38h country-information case-map far-call entry.
pub(super) const SLOT_COUNTRY_UPCASE: u8 = 0x17;

/// DOS country-info case map for the active guest code page.
pub(super) fn country_upcase(ch: u8) -> u8 {
    lib::codepage::current_codepage().uppercase(ch)
}

pub(crate) const fn vbe_window_ptr() -> u32 {
    ctrl_slot_off(SLOT_VBE_WINDOW) as u32
}
/// Return target for guest calls chained through the native video ROM.
/// Generic block-and-retry resume slot. A syscall that can't complete
/// synchronously (e.g. AH=08 with no key in the buffer) stores a continuation
/// in `dos.suspended_calls` and returns its interrupt to this stub. Each
/// event-loop iteration re-traps here, the dispatcher re-invokes the
/// closure; completion enters its stored return target directly. The original
/// soft-interrupt frame was already popped on the initial return to this stub.
pub(crate) const SLOT_RESUME: u8 = 0x76;
pub(crate) const SLOT_SAVE_RESTORE: u8 = 0xFD;
/// DPMI 0.9 exception RETF target. Handler installed via Function
/// 0203H pops the FAR-call return at the bottom of the spec frame and
/// lands here; kernel reads handler-modified faulting fields from the
/// 0.9 portion (at +00..+1FH in the frame) and discards the rest.
pub(crate) const SLOT_EXCEPTION_RET: u8 = 0xFE;
/// DPMI 1.0 expanded-frame exception RETF target. Handler installed
/// via Function 0212H/0213H does `ADD (E)SP, 0x20; RETF` to skip past
/// the 0.9 portion and pops the FAR-call return at the +20H slot of
/// the expanded frame, landing here; kernel reads handler-modified
/// faulting fields from the 1.0 expanded portion (at +20H..+57H).
pub(crate) const SLOT_EXCEPTION_RET_V10: u8 = 0xFB;
pub(crate) const SLOT_PM_TO_REAL: u8 = 0xFF;
/// PMDOS INT 21 short-circuit. When `dpmi.pm_dos` is set (16-bit DPMI
/// clients by default), `pm_vectors[0x21]` points here instead of the
/// generic vector stub. The CD 31 traps to `pmdos_int21_handler` which
/// runs the DOS INT 21 dispatcher with PM regs intact (no mode switch),
/// then pops the frame `deliver_pm_int` planted on the client's PM stack. `seg_offset()` sees `regs.mode() == PM` and resolves DS:DX via
/// LDT base lookup — so high-memory PM-block buffers (the case Borland's
/// `dpmiload` hits) are addressed correctly without bounce buffering.
pub(crate) const SLOT_PMDOS_INT21: u8 = 0xFC;
/// PM INT 33h (mouse) direct-service slot. `dpmi_enter` points
/// `pm_vectors[0x33]` here for every DPMI client so a PM `int 33h` is
/// serviced in protected mode with PM regs intact, rather than reflected to
/// real mode. This is what lets `int_33h` see `regs.mode() == PM` (so AX=0Ch
/// records `cb_is_pm`) and read `ES:DX` as a real selector:offset. The RM-side
/// INT 33h still routes through STUB_SEG slot 0x33 (the IVT redirect).
pub(crate) const SLOT_PMDOS_INT33: u8 = 0xFA;
/// PM INT 10h direct service; see [`pmdos_int10_handler`].
pub(crate) const SLOT_PMDOS_INT10: u8 = 0xF9;
/// Single continuation return target. Reflected INTs, explicit DPMI RM calls,
/// PM callback returns, and PM IRQ unwind all land here after their far return
/// or IRET. `mode_transitions::resume_continuation_from_stub` pops the captured
/// HostContinuation; an attached RmCallStruct address selects register-block
/// exchange.
pub(crate) const SLOT_RESUME_CONTINUATION: u8 = 0x02;

pub(crate) const fn slot_offset(slot: u8) -> u16 { (slot as u16) * 2 }

pub(in crate::kernel::dos) fn setup_ivt<A: crate::Arch>(machine: &mut A, regs: &mut Regs) {
    // Fill the stub array with `CD 31` so any slot reached by an IVT entry
    // (or PM CALL FAR) traps to STUB_INT and the slot dispatcher.
    let stubs = lm_field(core::mem::offset_of!(LowMem, stubs));
    for i in 0..256 {
        machine.write::<[u8; 2]>(stubs + i * 2, [0xCD, STUB_INT]);
    }
    // A blocked DOS operation must stop executing guest instructions until
    // the event loop polls it again. HLT traps uniformly in VM86 and PM and
    // avoids turning a modeled CD delay into millions of nested INT 31h
    // entries. The second byte is another HLT for defensive fall-through;
    // `poll_suspended_call` rewinds to byte zero while still waiting.
    machine.write::<[u8; 2]>(
        stubs + SLOT_RESUME as usize * 2,
        [0xF4, 0xF4],
    );

    // DOS always sees the Rust substitute BIOS. Native firmware is a private
    // implementation detail of BiosDisplayWorkspace and is never entered in
    // a personality's address space.
    crate::kernel::dos::bios::install(machine);

    // HW IRQ vectors are substitute-BIOS entries too. `raise_pending` delivers
    // through the PM vector table when required; real-mode delivery reaches
    // the same Rust vector stubs.

    // Hook the DOS/BIOS soft INTs we intercept so guest CD nn lands in our
    // dispatcher (slot index = INT vector).
    for &int_num in &[0x13u8, 0x20, 0x21, 0x25, 0x26, 0x28, 0x29, 0x2E, 0x2F, 0x33, 0x67] {
        write_u16(machine, 0, (int_num as u32) * 4, slot_offset(int_num));
        write_u16(machine, 0, (int_num as u32) * 4 + 2, STUB_SEG);
    }

    setup_lol_sft(machine, regs);
    xms::scan_uma(machine);

    // Force NumLock OFF in the BIOS keyboard-flags byte (40:17 bit 5). The
    // grey arrow keys are E0-stripped down to their numpad twins (Up == 0x48
    // == numpad-8) before the BIOS sees them, so with NumLock on the BIOS
    // renders them as digits ('8'/'2') instead of navigation — and a laptop
    // keyboard may have no NumLock key to clear it. 86box boots NumLock on;
    // QEMU/Bochs boot it off, which is why arrows worked there.
    let kbd_flags = crate::kernel::dos::Bda::keyboard_flags(machine) & !0x20;
    crate::kernel::dos::Bda::set_keyboard_flags(machine, kbd_flags);
}

fn setup_lol_sft<A: crate::Arch>(machine: &mut A, _regs: &mut Regs) {
    let sft_addr = LOW_MEM_BASE + core::mem::offset_of!(LowMem, sft) as u32;
    let cds_addr = LOW_MEM_BASE + core::mem::offset_of!(LowMem, cds) as u32;
    let cdrom_header_addr = LOW_MEM_BASE + core::mem::offset_of!(LowMem, cdrom_header) as u32;
    let cdrom_retf_addr = LOW_MEM_BASE + core::mem::offset_of!(LowMem, cdrom_retf) as u32;
    let boot_seg = ((LOW_MEM_BASE + core::mem::offset_of!(LowMem, boot_psp) as u32) >> 4) as u16;

    // Bootstrap sentinel PSP: self-referencing parent_psp terminates any
    // PSP[0x16] walk, env_seg = 0 (env defaults live in MASTER_ENV
    // const, not on the chain). The cmdline area at 0x80+ is otherwise
    // unused and gives us a permanent zero byte at the INDOS-flag offset.
    Psp::store(machine, boot_seg, Psp {
        int_20: [0xCD, 0x20],
        top_of_mem: 0xA000,
        parent_psp: boot_seg,         // self-ref terminates the parent chain
        env_seg: 0,
        ..Default::default()
    });

    let last_drive = dfs::last_drive(crate::kernel::platform::get().hostfs);
    let lol = Lol {
        sft_off: (sft_addr & 0xF) as u16,
        sft_seg: (sft_addr >> 4) as u16,
        cds_off: (cds_addr & 0xF) as u16,
        cds_seg: (cds_addr >> 4) as u16,
        block_devs: 2,
        last_drive,
        ..Default::default()
    };
    machine.write::<Lol>(lm_field(core::mem::offset_of!(LowMem, lol)), lol);

    // SFT header: end-of-chain link, entry count + zeroed entries; then
    // pre-populate stdin/stdout/stderr as character devices.
    let mut sft = Sft { next: 0xFFFF_FFFF, count: SFT_ENTRIES as u16, ..Default::default() };
    for fd in 0..3 {
        sft.entries[fd] = SftEntry {
            refcount: 1,
            device_info: if fd == 0 { 0x81 } else { 0x82 },
            ..Default::default()
        };
    }
    machine.write::<Sft>(lm_field(core::mem::offset_of!(LowMem, sft)), sft);

    // CDS: C: is the data disk, D: the hot-swappable CD-ROM, H: hostfs.
    // Programs such as Dos Navigator read this table directly rather than
    // deriving drive validity from AH=0Eh, so it must agree with DFS.
    let mk = |drive_letter: u8| -> CdsEntry {
        let mut e = CdsEntry::default();
        e.path[0] = drive_letter;
        e.path[1] = b':';
        e.path[2] = b'\\';
        e.flags = 0x4000;
        e.backslash_off = 2;
        e
    };
    let mut cds = [(); NUM_DRIVES as usize].map(|_| CdsEntry::default());
    // A:/B: are valid drives with or without media (MS-DOS binds letters to
    // drive units, not disks); an empty slot errors at access time instead.
    cds[0] = mk(b'A');
    cds[1] = mk(b'B');
    cds[2] = mk(b'C');
    cds[3] = mk(b'D');
    for letter in b'E'..=b'L' {
        if dfs::drive_available(letter, crate::kernel::platform::get().hostfs) {
            cds[usize::from(letter - b'A')] = mk(letter);
        }
    }
    machine.write::<[CdsEntry; NUM_DRIVES as usize]>(lm_field(core::mem::offset_of!(LowMem, cds)), cds);

    // Diskette parameter table (1.44M defaults: 512-byte sectors, 18 spt,
    // conventional step/settle timings), pointed at by IVT 1Eh per BIOS
    // convention and returned by INT 13h AH=08h in ES:DI.
    let ddpt_addr = LOW_MEM_BASE + core::mem::offset_of!(LowMem, ddpt) as u32;
    machine.write::<[u8; 11]>(
        ddpt_addr as usize,
        [0xAF, 0x02, 0x25, 0x02, 18, 0x1B, 0xFF, 0x6C, 0xF6, 0x0F, 0x08],
    );
    write_u16(machine, 0, 0x1E * 4, (ddpt_addr & 0xF) as u16);
    write_u16(machine, 0, 0x1E * 4 + 2, (ddpt_addr >> 4) as u16);

    // MSCDEX 1501h exposes this header. The two request entry offsets are
    // valid far-call targets even before the full device request API exists.
    let header_segment_base = cdrom_header_addr & !0xF;
    let retf_off = (cdrom_retf_addr - header_segment_base) as u16;
    machine.write::<CdromDeviceHeader>(
        cdrom_header_addr as usize,
        CdromDeviceHeader {
            next: u32::MAX,
            attributes: 0xC800, // character, IOCTL, open/close, CD-ROM
            strategy: retf_off,
            interrupt: retf_off,
            name: *b"MSCD001 ",
            reserved: 0,
            drive_letter: 4, // DOS block-device numbering: D: == 4
            subunits: 1,
        },
    );
    machine.write::<u8>(cdrom_retf_addr as usize, 0xCB);
}

/// Linear address of `LowMem.sft.entries[handle]`.
#[inline]
fn sft_entry_addr(handle: usize) -> usize {
    lm_field(core::mem::offset_of!(LowMem, sft) + core::mem::offset_of!(Sft, entries)
        + handle * core::mem::size_of::<SftEntry>())
}

/// Populate SFT entry for a newly opened file handle.
pub(super) fn sft_set_file<A: crate::Arch>(machine: &mut A, handle: u16, size: u32) {
    if handle as usize >= SFT_ENTRIES { return; }
    machine.write::<SftEntry>(sft_entry_addr(handle as usize), SftEntry {
        refcount: 1,
        attribute: 0x20,    // archive
        time: 0x6000,       // 12:00:00
        date: 0x5C76,       // 2026-03-22
        size,
        ..Default::default()
    });
}

/// Clear SFT entry when a file handle is closed.
pub(super) fn sft_clear<A: crate::Arch>(machine: &mut A, handle: u16) {
    if handle as usize >= SFT_ENTRIES { return; }
    machine.write::<u16>(sft_entry_addr(handle as usize) + core::mem::offset_of!(SftEntry, refcount), 0);
}
