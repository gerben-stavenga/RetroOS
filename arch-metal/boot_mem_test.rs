mod paging2 {
    pub const KERNEL_BASE: usize = 0;
    pub const KERNEL_PHYS: usize = 0;
    pub const BOOT_IDENTITY_END: usize = usize::MAX;
}
#[allow(dead_code)]
#[path = "src/boot_mem.rs"]
mod boot_mem;
