/// Number of LDT entries
pub(in crate::kernel::dos) const LDT_ENTRIES: usize = 8192;

/// LDT index of the "low memory" selector. Base=0, limit=1MB, 16-bit.
/// DOS handlers that need to return a pointer to a fixed low-memory byte
/// (INDOS flag, LOL, IVT vectors) use this as ES; BX is the linear address.
pub(super) const LOW_MEM_LDT_IDX: usize = 5;

/// Selector value for LOW_MEM_LDT_IDX (TI=1, RPL=3).
pub(in crate::kernel::dos) const LOW_MEM_SEL: u16 = ((LOW_MEM_LDT_IDX as u16) << 3) | 4 | 3;

/// LDT index of the PSP selector (ES on return from dpmi_enter).
/// Matches CWSDPMI's `l_apsp = 18` so DOS/4GW's first dynamic alloc lands at
/// LDT[20] (sel 0xA7) — same as CWSDPMI.
pub(super) const PSP_LDT_IDX: usize = 18;

/// Selector value for PSP_LDT_IDX (TI=1, RPL=3).
pub(in crate::kernel::dos) const PSP_SEL: u16 = ((PSP_LDT_IDX as u16) << 3) | 4 | 3;

/// LDT indices for the client's initial CS/DS/SS. Matches CWSDPMI's
/// l_acode=16, l_adata=17, l_apsp=18 layout. SS lives at l_aenv=19 (CWSDPMI
/// uses that slot for the env pointer; RetroOS allocates the env selector
/// dynamically). LDT[1..15] stays null so DOS/4GW's "lar probe" sees the
/// CWSDPMI-shaped empty range.
pub(super) const CLIENT_CS_LDT_IDX: usize = 16;
pub(super) const CLIENT_DS_LDT_IDX: usize = 17;
pub(super) const CLIENT_SS_LDT_IDX: usize = 19;
/// Maximum DPMI memory blocks
const MAX_MEM_BLOCKS: usize = 256;
/// Base address for DPMI linear memory allocations
pub(in crate::kernel::dos) const MEM_BASE: u32 = 0x0050_0000;

/// Exclusive upper bound of the dedicated DPMI physical-mapping window.
/// Keep it below the user stack at 0xC0000000. Allocations grow downward.
pub(in crate::kernel::dos) const PHYS_MAP_TOP: u32 = 0xB000_0000;

/// Do not allow the physical-mapping window to grow below this address.
const PHYS_MAP_FLOOR: u32 = 0xA000_0000;

/// Maximum simultaneous mappings owned by one DPMI client.
const MAX_PHYS_MAPPINGS: usize = 32;

/// Maximum number of real-mode callbacks (INT 31h/0303h)
const MAX_CALLBACKS: usize = 16;

/// Processor exception-vector namespace exposed by DPMI services 0202H/0203H
/// and 0210H..0213H: vectors 00H through 1FH, including CPU-reserved slots.
pub(super) const NUM_EXCEPTION_VECTORS: usize = 32;

pub(super) fn exception_index(vector: u8) -> Option<usize> {
    let index = usize::from(vector);
    (index < NUM_EXCEPTION_VECTORS).then_some(index)
}

/// Per-thread DPMI state (heap-allocated, attached to Thread.dpmi).
/// The LDT and `pm_vectors` live on `DosState` — always allocated at thread
/// init — so DPMI entry/exit doesn't have to (re)allocate them. See
/// `feedback_ldt_in_dpmi.md`.
pub struct DpmiState {
    /// Linear memory blocks allocated via INT 31h/0501h
    pub(super) mem_blocks: [Option<MemBlock>; MAX_MEM_BLOCKS],
    /// Bump allocator for linear memory (next free address)
    pub(super) mem_next: u32,
    /// Physical mappings made by INT 31h/0800h and owned by this client.
    pub(super) phys_mappings: [Option<PhysicalMapping>; MAX_PHYS_MAPPINGS],
    /// DPMI 0.9 exception handler vectors (set via INT 31h/0203H).
    /// A 0.9 handler covers BOTH PM-origin and VM86-origin faults for
    /// the vector; it serves as the fallback whenever the matching
    /// 1.0-specific table below has slot (0, 0).
    pub(super) exc_vectors: [(u16, u32); NUM_EXCEPTION_VECTORS],
    /// DPMI 1.0 protected-mode exception handler vectors (set via
    /// INT 31h/0212H). Consulted first when a fault originated in PM
    /// (`from_vm86 == false`); takes precedence over the 0.9 fallback.
    pub(super) pm_exc_vectors: [(u16, u32); NUM_EXCEPTION_VECTORS],
    /// DPMI 1.0 real-mode exception handler vectors (set via INT
    /// 31h/0213H). Consulted first when a fault originated in VM86
    /// (`from_vm86 == true`); takes precedence over the 0.9 fallback.
    /// Per DPMI 1.0 §6.1.4 the handler runs in PM with an implied
    /// mode switch — the selector:offset is a PM target, not a real
    /// segment:offset.
    pub(super) rm_exc_vectors: [(u16, u32); NUM_EXCEPTION_VECTORS],
    /// Real-mode callbacks (INT 31h/0303h)
    /// Each entry: Some((pm_cs, pm_eip, rm_struct_sel, rm_struct_off))
    pub(super) callbacks: [Option<(u16, u32, u16, u32)>; MAX_CALLBACKS],
    /// Client mode bit-width as declared at INT 2F/1687h → entry point.
    /// Determines the operand size used for FAR CALL/INT frames the client
    /// places on its own stack (4 vs 8 bytes for CALL FAR, 6 vs 12 bytes for
    /// INT). The stub LDT segment itself is 16-bit, so we can't infer this
    /// from the trapped CS — we must remember what the client declared.
    pub(in crate::kernel::dos) client_use32: bool,
    /// RM PSP segment captured at `dpmi_enter`. `dos.current_psp` remains a
    /// segment; this field identifies the PSP whose LDT[18] view and env word
    /// were installed for the DPMI client.
    pub(in crate::kernel::dos) saved_rm_psp: u16,
    /// Original PSP[0x2C] value (RM env paragraph) captured at DPMI entry.
    /// The in-memory word contains an env selector while the client runs.
    pub(in crate::kernel::dos) saved_rm_env: u16,
    /// LDT slot of the env selector allocated at DPMI entry, or 0 for a null
    /// environment or allocation failure. Non-zero implies PSP[0x2C] of
    /// `saved_rm_psp` is currently patched with `idx_to_sel(env_ldt_idx)`.
    pub(in crate::kernel::dos) env_ldt_idx: usize,
    /// Number of nested exception handlers using the fixed exception-stack
    /// slots. Continuations themselves are stored in LockedStackState.
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

/// One externally-owned physical-device mapping.
#[derive(Clone, Copy)]
pub(super) struct PhysicalMapping {
    /// Page-aligned physical device address backing this mapping.
    pub(super) physical_page_base: u32,
    /// Exact (possibly unaligned) linear address returned to the client.
    pub(super) returned_linear: u32,
    /// Page-aligned user virtual base.
    pub(super) virtual_page_base: u32,
    /// Number of 4 KiB pages in the mapping.
    pub(super) page_count: u32,
}

impl DpmiState {
    pub(super) fn new() -> Self {
        Self {
            mem_blocks: [None; MAX_MEM_BLOCKS],
            mem_next: MEM_BASE,
            phys_mappings: [None; MAX_PHYS_MAPPINGS],
            exc_vectors: [(0, 0); NUM_EXCEPTION_VECTORS],
            pm_exc_vectors: [(0, 0); NUM_EXCEPTION_VECTORS],
            rm_exc_vectors: [(0, 0); NUM_EXCEPTION_VECTORS],
            callbacks: [None; MAX_CALLBACKS],
            client_use32: false,
            saved_rm_psp: 0,
            saved_rm_env: 0,
            env_ldt_idx: 0,
            exc_depth: 0,
            psp_cache: [PspCacheEntry::default(); MAX_PSP_CACHE],
            vif: super::vif::VifMap::new(),
        }
    }

    /// Release all device mappings owned by this client. Required both for
    /// thread exit and when an EXEC child returns to its suspended parent.
    pub(in crate::kernel::dos) fn unmap_all_physical<A: crate::Arch>(
        &mut self,
        machine: &mut A,
    ) {
        for slot in self.phys_mappings.iter_mut() {
            if let Some(mapping) = slot.take() {
                machine.unmap_range(
                    (mapping.virtual_page_base >> 12) as usize,
                    mapping.page_count as usize,
                );
            }
        }
    }

    pub(super) fn free_phys_slot(&self) -> Option<usize> {
        self.phys_mappings.iter().position(Option::is_none)
    }

    pub(super) fn physical_mapping(
        &self,
        returned_linear: u32,
    ) -> Option<(usize, PhysicalMapping)> {
        self.phys_mappings
            .iter()
            .enumerate()
            .find_map(|(idx, entry)| {
                entry
                    .filter(|mapping| mapping.returned_linear == returned_linear)
                    .map(|mapping| (idx, mapping))
            })
    }
}

/// Calculate a downward-growing mapping without mutating allocator state.
/// Returns (new cursor/page base, page count, exact returned linear address).
pub(super) fn physical_mapping_layout(
    cursor: u32,
    physical: u32,
    size: u32,
) -> Option<(u32, u32, u32)> {
    if size == 0 {
        return None;
    }
    // The DPMI interface describes one non-wrapping 32-bit physical range.
    physical.checked_add(size - 1)?;
    let offset = physical & 0xFFF;
    let span = offset.checked_add(size)?;
    let page_count = span.checked_add(0xFFF)? >> 12;
    let bytes = page_count.checked_mul(0x1000)?;
    let virtual_base = cursor.checked_sub(bytes)? & !0xFFF;
    if virtual_base < PHYS_MAP_FLOOR {
        return None;
    }
    Some((
        virtual_base,
        page_count,
        virtual_base.checked_add(offset)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::{exception_index, physical_mapping_layout};

    #[test]
    fn exception_vector_namespace_includes_reserved_cpu_slots() {
        assert_eq!(exception_index(0x00), Some(0x00));
        assert_eq!(exception_index(0x0f), Some(0x0f));
        assert_eq!(exception_index(0x1f), Some(0x1f));
        assert_eq!(exception_index(0x20), None);
        assert_eq!(exception_index(0xff), None);
    }

    #[test]
    fn physical_mapping_layout_aligned() {
        assert_eq!(
            physical_mapping_layout(0xB000_0000, 0xFD00_0000, 0x2000),
            Some((0xAFFF_E000, 2, 0xAFFF_E000)),
        );
    }

    #[test]
    fn physical_mapping_layout_preserves_offset_and_crossing() {
        assert_eq!(
            physical_mapping_layout(0xB000_0000, 0xE000_0123, 0x1000),
            Some((0xAFFF_E000, 2, 0xAFFF_E123)),
        );
    }

    #[test]
    fn physical_mapping_layout_rejects_bad_ranges() {
        assert_eq!(physical_mapping_layout(0xB000_0000, 0, 0), None);
        assert_eq!(
            physical_mapping_layout(0xB000_0000, 0xFFFF_FFFF, u32::MAX),
            None,
        );
        assert_eq!(
            physical_mapping_layout(0xA000_1000, 0, 0x2000),
            None,
        );
    }
}
