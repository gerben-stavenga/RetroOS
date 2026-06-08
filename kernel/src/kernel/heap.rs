//! Metal global-allocator binding.
//!
//! The allocator *algorithm* is `lib::heap::DemandHeap` (a freestanding
//! demand-paged linked-list heap). This module is just the binary's binding:
//! install it as the metal `#[global_allocator]` and point it at the kernel-heap
//! virtual window, whose bounds the arch backend owns (`arch::{heap_base,
//! HEAP_END}`) and whose pages the arch `#PF` handler backs on first access.
//!
//! Hosted builds don't compile this module at all (std provides the allocator);
//! see the stub in `kernel/mod.rs`.

#[global_allocator]
static ALLOCATOR: lib::heap::DemandHeap = lib::heap::DemandHeap::new();

/// Initialize the kernel heap over the arch-owned VA window. Called once after
/// paging is up.
pub fn init() {
    ALLOCATOR.init(crate::arch::heap_base(), crate::arch::HEAP_END);
    crate::println!("Heap base: {:#x}", crate::arch::heap_base());
}
