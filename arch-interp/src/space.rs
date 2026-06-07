//! Software address space — the interpreter's analogue of a page-table root.

/// Handle to one software address space (the interpreter's analogue of the
/// metal backend's page-table root). The kernel treats it as an opaque blob:
/// it stores one in each `Vcpu`/`Thread` and hands it back to `arch_switch_to`
/// / `arch_user_fork`. The interpreter maps it to its per-space software MMU
/// (built out in Milestone 3); for now it is just an identifier.
#[derive(Clone, Copy)]
pub struct RootPageTable(pub u32);

impl RootPageTable {
    pub const fn empty() -> Self {
        RootPageTable(0)
    }
}

impl Default for RootPageTable {
    fn default() -> Self { RootPageTable::empty() }
}

/// Interpreter analogue of the metal kernel's statically-allocated page-table
/// frames. The hosted kernel has no boot-time paging bring-up, so nothing
/// constructs this; it exists only for surface parity with the metal backend.
pub struct KernelPages;
