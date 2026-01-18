//! RetroOS Rust Kernel
//!
//! Entry flow:
//! 1. PrepareKernel (runs at physical address, paging off, uses delta adjustment)
//! 2. SwitchStack (assembly, switches to kernel stack)
//! 3. KernelInit (runs with paging, at KERNEL_BASE)

#![no_std]
#![no_main]

use core::panic::PanicInfo;

extern crate alloc;

pub mod descriptors;
pub mod heap;
pub mod elf;
pub mod irq;
pub mod paging2;
pub mod phys_mm;
pub mod startup;
pub mod syscalls;
pub mod thread;
pub mod traps;
pub mod x86;

// Re-export lib's vga module and macros
pub use lib::vga;
pub use lib::{print, println};

use paging2::{KernelPages, PAGE_SIZE, LOW_MEM_BASE};

use crate::paging2::RawPage;

/// Memory map entry from bootloader
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct MMapEntry {
    pub base: u64,
    pub length: u64,
    pub typ: u32,
    pub acpi: u32,
}

/// Boot data passed from bootloader
#[repr(C)]
pub struct BootData {
    pub kernel: *const u8,
    pub start_sector: u32,
    pub cursor_pos: u32,
    pub mmap_count: i32,
    pub mmap_entries: [MMapEntry; 32],
}

static ZERO_PAGE: RawPage = unsafe { core::mem::zeroed() };
static mut SCRATCH: RawPage = unsafe { core::mem::zeroed() };

/// Kernel pages - statically allocated page tables
static mut KERNEL_PAGES: KernelPages = unsafe { core::mem::zeroed() };

/// Kernel stack - 128KB
static mut KERNEL_STACK: [u8; 128 * 1024] = [0; 128 * 1024];

// External assembly functions
unsafe extern "C" {
    fn SwitchStack(new_stack: *mut u8, func: *const ()) -> !;
}

// Linker symbols
unsafe extern "C" {
    static _start: u8;
    static _data: u8;
    static _edata: u8;
    static _end: u8;
}

/// PrepareKernel - Entry point called by bootloader
///
/// This function runs at physical address with paging disabled.
/// The kernel is linked at KERNEL_BASE but loaded at arbitrary phys address.
/// We use delta adjustment to access globals correctly.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn PrepareKernel(boot_data: *const BootData) -> ! {
    unsafe {
        let phys_address = (*boot_data).kernel as usize;
        let linked_address = core::ptr::addr_of!(_start) as usize;

        // Delta between where we're loaded and where we're linked
        let delta = phys_address.wrapping_sub(linked_address);

        // Adjust a pointer from linked address to physical address
        let adjust = |ptr: *const u8| -> *mut u8 {
            (ptr as usize).wrapping_add(delta) as *mut u8
        };

        // Get adjusted pointers to kernel pages and scratch
        let kpages = adjust(core::ptr::addr_of!(KERNEL_PAGES) as *const u8) as *mut KernelPages;
        let scratch = adjust(core::ptr::addr_of!(SCRATCH) as *const u8) as *mut RawPage;

        // Calculate kernel size in pages
        let kernel_size = core::ptr::addr_of!(_end) as usize - linked_address;
        let kernel_pages = (kernel_size + PAGE_SIZE - 1) / PAGE_SIZE;

        // Enable paging (auto-detects Legacy vs PAE)
        paging2::enable_paging(kpages, scratch, phys_address, kernel_pages);

        // Now paging is enabled, we're running at virtual address
        // Set up argument for KernelInit on the stack
        #[allow(static_mut_refs)]
        let stack_top = unsafe { KERNEL_STACK.as_mut_ptr_range().end };
        // Push boot_data pointer (adjusted to LOW_MEM_BASE mapping)
        let boot_data_virt = (boot_data as usize + LOW_MEM_BASE) as *const BootData;
        let stack_with_arg = stack_top.sub(4) as *mut *const BootData;
        *stack_with_arg = boot_data_virt;

        SwitchStack(stack_with_arg as *mut u8, KernelInit as *const ());
    }
}

/// Main kernel initialization
///
/// This runs on the kernel stack with paging enabled.
extern "C" fn KernelInit(boot_data: *const BootData) -> ! {
    let boot_data = unsafe { &*boot_data };

    println!("\x1b[96mRetroOS Rust Kernel\x1b[0m");

    // Update VGA base to use LOW_MEM_BASE mapping before removing identity
    vga::vga().base = LOW_MEM_BASE + 0xB8000;

    // Remove identity mapping now that we're running at virtual addresses
    paging2::remove_identity_mapping();

    println!("Accessing boot_data...");

    // Get kernel physical address from boot_data
    let kernel_phys = boot_data.kernel as usize;
    println!("kernel_phys: {:#x}", kernel_phys);

    let kernel_size = core::ptr::addr_of!(_end) as usize - core::ptr::addr_of!(_start) as usize;
    let kernel_low_page = kernel_phys / PAGE_SIZE;
    let kernel_high_page = (kernel_phys + kernel_size + PAGE_SIZE - 1) / PAGE_SIZE;

    println!("Initializing phys_mm...");

    // Initialize physical memory allocator
    phys_mm::init_phys_mm(
        &boot_data.mmap_entries,
        boot_data.mmap_count as usize,
        kernel_low_page,
        kernel_high_page,
    );
    println!("Physical memory: {:#x} pages free", phys_mm::free_page_count());

    // Initialize kernel heap allocator
    heap::init();
    println!("Heap initialized");

    // Print memory map
    let boot_data = boot_data;
    println!("Memory regions: {}", boot_data.mmap_count);

    for i in 0..boot_data.mmap_count as usize {
        if i >= 32 { break; }
        let entry = boot_data.mmap_entries[i];
        if entry.typ == 1 {
            // Copy packed fields before use to avoid unaligned references
            let base = entry.base;
            let length = entry.length;
            println!("  Available: {:#x} - {:#x}", base, base + length);
        }
    }

    // Setup GDT, IDT, TSS
    #[allow(static_mut_refs)]
    let stack_top = unsafe { (KERNEL_STACK.as_ptr_range().end) as u32 };
    descriptors::setup_descriptor_tables(stack_top);
    println!("Descriptors initialized");

    // Setup PIC and enable interrupts
    irq::init_interrupts();
    println!("Interrupts initialized");

    // Initialize threading
    thread::init_threading();
    println!("Threading initialized");

    println!();
    println!("\x1b[92mHello from Rust kernel!\x1b[0m");

    // Check CPU capabilities
    if paging2::cpu_supports_pae() {
        println!("CPU supports PAE");
    }
    if paging2::cpu_supports_long_mode() {
        println!("CPU supports Long Mode (64-bit)");
    }

    // Enable interrupts
    x86::sti();
    println!("Interrupts enabled");

    // Halt loop with interrupts enabled
    loop {
        x86::hlt();
    }
}

/// CPU register state saved by interrupt handler
#[repr(C)]
pub struct Regs {
    pub gs: u32,
    pub fs: u32,
    pub es: u32,
    pub ds: u32,
    pub edi: u32,
    pub esi: u32,
    pub ebp: u32,
    pub esp_dummy: u32,
    pub ebx: u32,
    pub edx: u32,
    pub ecx: u32,
    pub eax: u32,
    pub int_num: u32,
    pub err_code: u32,
    pub eip: u32,
    pub cs: u32,
    pub eflags: u32,
    pub user_esp: u32,
    pub user_ss: u32,
}

/// Panic handler
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!();
    println!("\x1b[91m!!! KERNEL PANIC !!!\x1b[0m");

    if let Some(location) = info.location() {
        println!("at {}:{}", location.file(), location.line());
    }

    if let Some(msg) = info.message().as_str() {
        println!("{}", msg);
    }

    loop {
        x86::cli();
        x86::hlt();
    }
}
