/// Number of LDT entries
pub(in crate::kernel::dos) const LDT_ENTRIES: usize = 8192;

/// LDT index of the "low memory" selector. Base=0, limit=1MB, 16-bit.
/// DOS handlers that need to return a pointer to a fixed low-memory byte
/// (INDOS flag, LOL, IVT vectors) use this as ES; BX is the linear address.
///
/// Internal-host slots are placed at LDT[200+] (well outside the LDT[1..127]
/// range that CWSDPMI uses) so DOS/4GW's `lar`-probe of low slots sees the
/// CWSDPMI-shaped empty range and we don't collide with client allocations.
pub(super) const LOW_MEM_LDT_IDX: usize = 5;

/// Selector value for LOW_MEM_LDT_IDX (TI=1, RPL=3).
pub(in crate::kernel::dos) const LOW_MEM_SEL: u16 = ((LOW_MEM_LDT_IDX as u16) << 3) | 4 | 3;

/// LDT index of the PSP selector (ES on return from dpmi_enter).
/// Matches CWSDPMI's l_apsp = 18.
/// Matches CWSDPMI's `l_apsp = 18` so DOS/4GW's first dynamic alloc lands at
/// LDT[20] (sel 0xA7) — same as CWSDPMI.
pub(super) const PSP_LDT_IDX: usize = 18;

/// Selector value for PSP_LDT_IDX (TI=1, RPL=3).
pub(in crate::kernel::dos) const PSP_SEL: u16 = ((PSP_LDT_IDX as u16) << 3) | 4 | 3;


/// LDT indices for the client's initial CS/DS/SS. Matches CWSDPMI's
/// l_acode=16, l_adata=17, l_apsp=18 layout. SS lives at l_aenv=19 (CWSDPMI
/// uses that slot for the env pointer; RetroOS doesn't separately allocate
/// env so we reuse 19 for SS). LDT[1..15] stays null so DOS/4GW's "lar
/// probe" sees the CWSDPMI-shaped empty range.
pub(super) const CLIENT_CS_LDT_IDX: usize = 16;
pub(super) const CLIENT_DS_LDT_IDX: usize = 17;
pub(super) const CLIENT_SS_LDT_IDX: usize = 19;




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
    pub(super) mem_blocks: [Option<MemBlock>; MAX_MEM_BLOCKS],
    /// Bump allocator for linear memory (next free address)
    pub(super) mem_next: u32,
    /// DPMI 0.9 exception handler vectors (set via INT 31h/0203H).
    /// A 0.9 handler covers BOTH PM-origin and VM86-origin faults for
    /// the vector; it serves as the fallback whenever the matching
    /// 1.0-specific table below has slot (0, 0). Spec-defined range
    /// is 0..14, but we keep 32 slots so the lookup tables share an
    /// index basis.
    pub(super) exc_vectors: [(u16, u32); 32],
    /// DPMI 1.0 protected-mode exception handler vectors (set via
    /// INT 31h/0212H). Consulted first when a fault originated in PM
    /// (`from_vm86 == false`); takes precedence over the 0.9 fallback.
    pub(super) pm_exc_vectors: [(u16, u32); 32],
    /// DPMI 1.0 real-mode exception handler vectors (set via INT
    /// 31h/0213H). Consulted first when a fault originated in VM86
    /// (`from_vm86 == true`); takes precedence over the 0.9 fallback.
    /// Per DPMI 1.0 §6.1.4 the handler runs in PM with an implied
    /// mode switch — the selector:offset is a PM target, not a real
    /// segment:offset.
    pub(super) rm_exc_vectors: [(u16, u32); 32],
    /// Real-mode callbacks (INT 31h/0303h)
    /// Each entry: Some((pm_cs, pm_eip, rm_struct_sel, rm_struct_off))
    pub(super) callbacks: [Option<(u16, u32, u16, u32)>; MAX_CALLBACKS],
    /// Client mode bit-width as declared at INT 2F/1687h → entry point.
    /// Determines the operand size used for FAR CALL/INT frames the client
    /// places on its own stack (4 vs 8 bytes for CALL FAR, 6 vs 12 bytes for
    /// INT). The stub LDT segment itself is 16-bit, so we can't infer this
    /// from the trapped CS — we must remember what the client declared.
    pub(in crate::kernel::dos) client_use32: bool,
    /// RM PSP segment captured on the most recent RM→PM transition (initial
    /// `dpmi_enter` or `raw_switch_real_to_pm`). The matching PM→RM transition
    /// uses this to restore `dos.current_psp`. While in PM, `dos.current_psp`
    /// is fixed at `PSP_SEL` and this field names the RM PSP that PSP_SEL's
    /// LDT[4] descriptor points at.
    pub(in crate::kernel::dos) saved_rm_psp: u16,
    /// Original PSP[0x2C] value (RM env paragraph) captured on the most
    /// recent RM→PM transition. For 32-bit clients we patch PSP[0x2C] with
    /// an env selector during PM execution; PM→RM restores from this field.
    /// For 16-bit clients PSP[0x2C] is left untouched but we still capture
    /// it so callers that want the RM env segment have a single source.
    pub(in crate::kernel::dos) saved_rm_env: u16,
    /// LDT slot of the env selector allocated for 32-bit clients on RM→PM,
    /// or 0 if none is currently allocated (16-bit client, null env, or
    /// PM→RM has run since the last RM→PM). Non-zero implies PSP[0x2C] of
    /// `saved_rm_psp` is currently patched with `idx_to_sel(env_ldt_idx)`.
    pub(in crate::kernel::dos) env_ldt_idx: usize,
    /// Where each in-flight exception dispatch pushed its HostContinuation:
    /// the pm-side (SS, SP) returned by `push_continuation_and_switch_to_pm_side`,
    /// with the spec exception frames written directly below it. LIFO —
    /// `dispatch_dpmi_exception` pushes, `exception_return` pops on the
    /// handler's RETF into the return stub. Recording the real cursor is
    /// what makes NESTED faults unwind correctly: a fault taken while a
    /// continuation chain is in flight (e.g. inside a kernel-delivered IRQ
    /// handler) pushes mid-stack — often on the client's own stack — where
    /// the old "empty host-stack top" assumption reads unrelated bytes.
    /// (A handler that abandons its frame instead of RETFing leaks one
    /// entry; the continuation chain itself has the same LIFO contract.)
    pub(super) exc_frames: [(u16, u32); MAX_EXC_NEST],
    /// Number of live entries in `exc_frames`.
    pub(super) exc_depth: usize,
    /// PSP segment → PM selector cache. HDPMI-style append-only mapping:
    /// each unique RM PSP segment queried from PM gets one stable LDT slot
    /// (descriptor base = segment*16, limit = 0xFF). AH=51/62 from PM
    /// returns the cached selector; AH=50 from PM reverses it to a segment
    /// before reflecting to RM DOS. `entry.selector == 0` marks an unused
    /// slot. Slot 0 is pre-populated at `dpmi_enter` with
    /// `(initial_psp, PSP_SEL)` so the well-known selector keeps its
    /// CWSDPMI-shape value for clients that probe.
    pub(super) psp_cache: [PspCacheEntry; MAX_PSP_CACHE],
    /// Virtual-IF state for this client's address space (per-CLI-site exit map +
    /// the open window). Owned here, dropped with the client. See `vif.rs`.
    pub(in crate::kernel::dos) vif: super::vif::VifMap,
}

/// Maximum tracked in-flight (dispatched, not yet returned) DPMI exceptions.
/// Real nesting is a fault inside an exception handler — depth 2–3 at the
/// extreme; 8 is comfortably beyond anything a client survives.
pub(super) const MAX_EXC_NEST: usize = 8;

/// Maximum simultaneous tracked PSPs in the per-client PSP selector cache.
/// HDPMI uses an unbounded linked list; 16 is plenty for the depths we see
/// (Borland's loader chain stays at 2–3, COMMAND.COM cmd.exe etc. add a few
/// more but never approach this).
pub(super) const MAX_PSP_CACHE: usize = 16;

/// One entry in the PSP selector cache. `selector == 0` means the slot is
/// free. The descriptor at LDT[selector>>3] has base = `segment * 16` and
/// limit 0xFF.
#[derive(Clone, Copy, Default)]
pub(super) struct PspCacheEntry {
    pub(super) segment: u16,
    pub(super) selector: u16,
}

/// A DPMI linear memory block
#[derive(Clone, Copy)]
pub(super) struct MemBlock {
    pub(super) base: u32,
    pub(super) size: u32,
}

impl DpmiState {
    pub(super) fn new() -> Self {
        Self {
            mem_blocks: [None; MAX_MEM_BLOCKS],
            mem_next: MEM_BASE,
            exc_vectors: [(0, 0); 32],
            pm_exc_vectors: [(0, 0); 32],
            rm_exc_vectors: [(0, 0); 32],
            callbacks: [None; MAX_CALLBACKS],
            client_use32: false,
            saved_rm_psp: 0,
            saved_rm_env: 0,
            env_ldt_idx: 0,
            exc_frames: [(0, 0); MAX_EXC_NEST],
            exc_depth: 0,
            psp_cache: [PspCacheEntry::default(); MAX_PSP_CACHE],
            vif: super::vif::VifMap::new(),
        }
    }
}
