/// Number of LDT entries
pub(in crate::kernel::dos) const LDT_ENTRIES: usize = 8192;

/// LDT index of the "low memory" selector. Base=0, limit=1MB, 16-bit.
/// DOS handlers that need to return a pointer to a fixed low-memory byte
/// (INDOS flag, LOL, IVT vectors) use this as ES; BX is the linear address.
///
/// Internal-host slots are placed at LDT[200+] (well outside the LDT[1..127]
/// range that CWSDPMI uses) so DOS/4GW's `lar`-probe of low slots sees the
/// CWSDPMI-shaped empty range and we don't collide with client allocations.
pub const LOW_MEM_LDT_IDX: usize = 5;

/// Selector value for LOW_MEM_LDT_IDX (TI=1, RPL=3).
pub const LOW_MEM_SEL: u16 = ((LOW_MEM_LDT_IDX as u16) << 3) | 4 | 3;

/// LDT index of the PSP selector (ES on return from dpmi_enter).
/// Matches CWSDPMI's l_apsp = 18.
/// Matches CWSDPMI's `l_apsp = 18` so DOS/4GW's first dynamic alloc lands at
/// LDT[20] (sel 0xA7) — same as CWSDPMI.
pub const PSP_LDT_IDX: usize = 18;

/// Selector value for PSP_LDT_IDX (TI=1, RPL=3).
pub const PSP_SEL: u16 = ((PSP_LDT_IDX as u16) << 3) | 4 | 3;


/// LDT indices for the client's initial CS/DS/SS. Matches CWSDPMI's
/// l_acode=16, l_adata=17, l_apsp=18 layout. SS lives at l_aenv=19 (CWSDPMI
/// uses that slot for the env pointer; RetroOS doesn't separately allocate
/// env so we reuse 19 for SS). LDT[1..15] stays null so DOS/4GW's "lar
/// probe" sees the CWSDPMI-shaped empty range.
pub const CLIENT_CS_LDT_IDX: usize = 16;
pub const CLIENT_DS_LDT_IDX: usize = 17;
pub const CLIENT_SS_LDT_IDX: usize = 19;




/// Maximum DPMI memory blocks
const MAX_MEM_BLOCKS: usize = 256;
/// Base address for DPMI linear memory allocations
pub(in crate::kernel::dos) const MEM_BASE: u32 = 0x0050_0000;

/// Maximum number of real-mode callbacks (INT 31h/0303h)
const MAX_CALLBACKS: usize = 16;

/// Per-thread DPMI state (heap-allocated, attached to Thread.dpmi).
/// The LDT and `pm_vectors` live on `DosState` — always allocated at thread
/// init — so DPMI entry/exit doesn't have to (re)allocate them. See
/// `feedback_ldt_in_dpmi.md`.
pub struct DpmiState {
    /// Linear memory blocks allocated via INT 31h/0501h
    pub mem_blocks: [Option<MemBlock>; MAX_MEM_BLOCKS],
    /// Bump allocator for linear memory (next free address)
    pub mem_next: u32,
    /// Hidden real-mode state for raw mode switches (INT 31h/0305h/0306h).
    pub raw_rm_state: RawModeState,
    /// Hidden protected-mode state for raw mode switches (INT 31h/0305h/0306h).
    pub raw_pm_state: RawModeState,
    /// DPMI 0.9 exception handler vectors (set via INT 31h/0203H).
    /// A 0.9 handler covers BOTH PM-origin and VM86-origin faults for
    /// the vector; it serves as the fallback whenever the matching
    /// 1.0-specific table below has slot (0, 0). Spec-defined range
    /// is 0..14, but we keep 32 slots so the lookup tables share an
    /// index basis.
    pub exc_vectors: [(u16, u32); 32],
    /// DPMI 1.0 protected-mode exception handler vectors (set via
    /// INT 31h/0212H). Consulted first when a fault originated in PM
    /// (`from_vm86 == false`); takes precedence over the 0.9 fallback.
    pub pm_exc_vectors: [(u16, u32); 32],
    /// DPMI 1.0 real-mode exception handler vectors (set via INT
    /// 31h/0213H). Consulted first when a fault originated in VM86
    /// (`from_vm86 == true`); takes precedence over the 0.9 fallback.
    /// Per DPMI 1.0 §6.1.4 the handler runs in PM with an implied
    /// mode switch — the selector:offset is a PM target, not a real
    /// segment:offset.
    pub rm_exc_vectors: [(u16, u32); 32],
    /// Real-mode callbacks (INT 31h/0303h)
    /// Each entry: Some((pm_cs, pm_eip, rm_struct_sel, rm_struct_off))
    pub callbacks: [Option<(u16, u32, u16, u32)>; MAX_CALLBACKS],
    /// Client mode bit-width as declared at INT 2F/1687h → entry point.
    /// Determines the operand size used for FAR CALL/INT frames the client
    /// places on its own stack (4 vs 8 bytes for CALL FAR, 6 vs 12 bytes for
    /// INT). The stub LDT segment itself is 16-bit, so we can't infer this
    /// from the trapped CS — we must remember what the client declared.
    pub client_use32: bool,
    /// RM PSP segment captured on the most recent RM→PM transition (initial
    /// `dpmi_enter` or `raw_switch_real_to_pm`). The matching PM→RM transition
    /// uses this to restore `dos.current_psp`. While in PM, `dos.current_psp`
    /// is fixed at `PSP_SEL` and this field names the RM PSP that PSP_SEL's
    /// LDT[4] descriptor points at.
    pub saved_rm_psp: u16,
    /// Original PSP[0x2C] value (RM env paragraph) captured on the most
    /// recent RM→PM transition. For 32-bit clients we patch PSP[0x2C] with
    /// an env selector during PM execution; PM→RM restores from this field.
    /// For 16-bit clients PSP[0x2C] is left untouched but we still capture
    /// it so callers that want the RM env segment have a single source.
    pub saved_rm_env: u16,
    /// LDT slot of the env selector allocated for 32-bit clients on RM→PM,
    /// or 0 if none is currently allocated (16-bit client, null env, or
    /// PM→RM has run since the last RM→PM). Non-zero implies PSP[0x2C] of
    /// `saved_rm_psp` is currently patched with `idx_to_sel(env_ldt_idx)`.
    pub env_ldt_idx: usize,
}

/// A DPMI linear memory block
#[derive(Clone, Copy)]
pub struct MemBlock {
    pub(super) base: u32,
    pub(super) size: u32,
}

/// Host-private alternate-mode state saved/restored by INT 31h/0305h.
///
/// The DPMI spec leaves the buffer format host-defined; clients only know the
/// size returned by AX=0305h and pass the buffer back to the save/restore
/// routine. We keep the hidden CS:IP, SS:SP, flags, and segment registers for
/// the non-current mode here so raw mode switches can be nested safely.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RawModeState {
    pub(super) flags: u32,
    pub(super) cs: u16,
    pub(super) ip: u32,
    pub(super) ss: u16,
    pub(super) sp: u32,
    pub(super) ds: u16,
    pub(super) es: u16,
    pub(super) fs: u16,
    pub(super) gs: u16,
}

impl DpmiState {
    pub fn new() -> Self {
        Self {
            mem_blocks: [None; MAX_MEM_BLOCKS],
            mem_next: MEM_BASE,
            raw_rm_state: RawModeState::default(),
            raw_pm_state: RawModeState::default(),
            exc_vectors: [(0, 0); 32],
            pm_exc_vectors: [(0, 0); 32],
            rm_exc_vectors: [(0, 0); 32],
            callbacks: [None; MAX_CALLBACKS],
            client_use32: false,
            saved_rm_psp: 0,
            saved_rm_env: 0,
            env_ldt_idx: 0,
        }
    }

    /// Convert LDT index to selector (TI=1, RPL=3)
    pub(super) fn idx_to_sel(idx: usize) -> u16 {
        ((idx as u16) << 3) | 4 | 3
    }

    /// Convert selector to LDT index
    pub(super) fn sel_to_idx(sel: u16) -> usize {
        (sel >> 3) as usize
    }

    /// Build a data descriptor (present, DPL=3, writable)
    /// `db` = D/B bit: false = 16-bit, true = 32-bit
    pub(super) fn make_data_desc_ex(base: u32, limit: u32, db: bool) -> u64 {
        let (limit_val, g) = if limit > 0xFFFFF {
            (limit >> 12, 1u64)
        } else {
            (limit, 0u64)
        };
        let access: u64 = 0xF2; // Present | DPL=3 | S=1 | Data | Writable
        let flags: u64 = (g << 7) | ((db as u64) << 6);
        build_descriptor(base, limit_val, access, flags)
    }

    /// Build a 32-bit data descriptor (present, DPL=3, writable)
    pub(super) fn make_data_desc(base: u32, limit: u32) -> u64 {
        Self::make_data_desc_ex(base, limit, true)
    }

    /// Build a code descriptor (present, DPL=3, readable)
    /// `db` = D bit: false = 16-bit, true = 32-bit
    pub(super) fn make_code_desc_ex(base: u32, limit: u32, db: bool) -> u64 {
        let (limit_val, g) = if limit > 0xFFFFF {
            (limit >> 12, 1u64)
        } else {
            (limit, 0u64)
        };
        let access: u64 = 0xFA; // Present | DPL=3 | S=1 | Code | Readable
        let flags: u64 = (g << 7) | ((db as u64) << 6);
        build_descriptor(base, limit_val, access, flags)
    }

    /// Build a 32-bit code descriptor (present, DPL=3, readable)
    #[allow(dead_code)]
    fn make_code_desc(base: u32, limit: u32) -> u64 {
        Self::make_code_desc_ex(base, limit, true)
    }

    /// Get the base address from an LDT descriptor
    pub fn desc_base(desc: u64) -> u32 {
        let b0 = ((desc >> 16) & 0xFFFF) as u32;
        let b1 = ((desc >> 32) & 0xFF) as u32;
        let b2 = ((desc >> 56) & 0xFF) as u32;
        b0 | (b1 << 16) | (b2 << 24)
    }

    /// Get the limit from an LDT descriptor (taking G bit into account)
    pub fn desc_limit(desc: u64) -> u32 {
        let l0 = (desc & 0xFFFF) as u32;
        let l1 = ((desc >> 48) & 0x0F) as u32;
        let raw = l0 | (l1 << 16);
        if desc & (1 << 55) != 0 { // G bit
            (raw << 12) | 0xFFF
        } else {
            raw
        }
    }

    /// Set base address in a descriptor
    pub(super) fn set_desc_base(desc: &mut u64, base: u32) {
        *desc &= !0xFF00_00FF_FFFF_0000;
        *desc |= ((base & 0xFFFF) as u64) << 16;
        *desc |= (((base >> 16) & 0xFF) as u64) << 32;
        *desc |= (((base >> 24) & 0xFF) as u64) << 56;
    }

    /// Match CWSDPMI's "segment to descriptor" reuse heuristic:
    /// 64 KiB byte-granularity descriptor with base == seg << 4.
    pub(super) fn desc_is_seg_alias(desc: u64, base: u32) -> bool {
        let lim0 = (desc & 0xFFFF) as u16;
        let lim1 = ((desc >> 48) & 0xFF) as u8;
        let base0 = ((desc >> 16) & 0xFFFF) as u16;
        let base1 = ((desc >> 32) & 0xFF) as u8;
        let base2 = ((desc >> 56) & 0xFF) as u8;

        lim0 == 0xFFFF
            && lim1 == 0
            && base2 == 0
            && base0 == (base as u16)
            && base1 == ((base >> 16) as u8)
    }

    /// Set limit in a descriptor (adjusts G bit)
    pub(super) fn set_desc_limit(desc: &mut u64, limit: u32) {
        let (lim, g) = if limit > 0xFFFFF {
            (limit >> 12, true)
        } else {
            (limit, false)
        };
        // Clear old limit bits and G bit
        *desc &= !0x000F_0000_0000_FFFF;
        *desc &= !(1u64 << 55); // clear G
        *desc |= (lim & 0xFFFF) as u64;
        *desc |= (((lim >> 16) & 0x0F) as u64) << 48;
        if g { *desc |= 1u64 << 55; }
    }
}

/// Build an x86 segment descriptor from components.
/// flags: high nibble of byte 6 — bit 7 = G, bit 6 = D/B, bit 5 = L, bit 4 = AVL.
fn build_descriptor(base: u32, limit: u32, access: u64, flags: u64) -> u64 {
    let mut desc: u64 = 0;
    desc |= (limit & 0xFFFF) as u64;                          // bits  0-15: Limit[15:0]
    desc |= ((base & 0xFFFF) as u64) << 16;                   // bits 16-31: Base[15:0]
    desc |= (((base >> 16) & 0xFF) as u64) << 32;             // bits 32-39: Base[23:16]
    desc |= (access & 0xFF) << 40;                             // bits 40-47: Access byte
    let byte6 = (((limit >> 16) & 0x0F) as u64) | (flags & 0xF0); // Limit[19:16] | G:D/B:L:AVL
    desc |= byte6 << 48;                                       // bits 48-55
    desc |= (((base >> 24) & 0xFF) as u64) << 56;             // bits 56-63: Base[31:24]
    desc
}
