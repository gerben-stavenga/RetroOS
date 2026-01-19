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
pub mod hdd;
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

    // Finish paging setup (remove identity, enable NX, setup long mode, harden)
    paging2::finish_setup_paging();

    println!("Accessing boot_data...");

    // Get kernel physical address from boot_data and set it for virt_to_phys
    let kernel_phys = boot_data.kernel as usize;
    paging2::set_kernel_phys_base(kernel_phys);
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

    // Mark zero page as reserved so COW always copies (ref count never decremented)
    let zero_page_phys = paging2::physical_page(&ZERO_PAGE as *const _ as usize);
    phys_mm::mark_reserved(zero_page_phys, zero_page_phys + 1);

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

    // Enable interrupts
    x86::sti();
    println!("Interrupts enabled");

    // Initialize threading
    thread::init_threading();
    println!("Threading initialized");

    println!();
    println!("\x1b[92mHello from Rust kernel!\x1b[0m");

    // Start the init process (never returns)
    startup::startup(boot_data.start_sector);
}

/// CPU-pushed interrupt frame for 32-bit mode
/// Padded at start to match Frame64 size (40 bytes total)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Frame32 {
    pub _pad: [u32; 5],  // 20 bytes padding
    pub eip: u32,
    pub cs: u32,
    pub eflags: u32,
    pub esp: u32,
    pub ss: u32,
}

impl core::fmt::Debug for Frame32 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Frame32")
            .field("eip", &format_args!("{:#010x}", self.eip))
            .field("cs", &format_args!("{:#06x}", self.cs))
            .field("eflags", &format_args!("{:#010x}", self.eflags))
            .field("esp", &format_args!("{:#010x}", self.esp))
            .field("ss", &format_args!("{:#06x}", self.ss))
            .finish()
    }
}

/// CPU-pushed interrupt frame for 64-bit mode
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Frame64 {
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

impl core::fmt::Debug for Frame64 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Frame64")
            .field("rip", &format_args!("{:#018x}", self.rip))
            .field("cs", &format_args!("{:#06x}", self.cs))
            .field("rflags", &format_args!("{:#018x}", self.rflags))
            .field("rsp", &format_args!("{:#018x}", self.rsp))
            .field("ss", &format_args!("{:#06x}", self.ss))
            .finish()
    }
}

/// Union for CPU-pushed interrupt frame (32-bit or 64-bit)
#[repr(C)]
#[derive(Clone, Copy)]
pub union Frame {
    pub f32: Frame32,
    pub f64: Frame64,
}

impl core::fmt::Debug for Frame {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Default to 32-bit view for now
        unsafe { self.f32.fmt(f) }
    }
}

/// CPU register state saved by interrupt handler
/// Uses u64 for software-pushed registers to support both 32-bit and 64-bit userspace.
/// The CPU frame is a union since the CPU pushes different sizes in different modes.
#[repr(C)]
pub struct Regs {
    // Segment registers (zero-extended)
    pub gs: u64,
    pub fs: u64,
    pub es: u64,
    pub ds: u64,
    // x86-64 extended registers (zero in 32-bit mode)
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    // General purpose registers
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rsp_dummy: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
    // Interrupt info (software-pushed, zero-extended to 64-bit)
    pub int_num: u64,
    pub err_code: u64,
    // CPU-pushed interrupt frame (layout depends on CPU mode)
    pub frame: Frame,
}

impl Regs {
    /// Get instruction pointer (works for both 32 and 64-bit modes)
    pub fn ip(&self) -> u64 {
        // In 32-bit mode, use f32.eip. In 64-bit mode, use f64.rip.
        // For now assume 32-bit kernel mode.
        unsafe { self.frame.f32.eip as u64 }
    }

    /// Get code segment
    pub fn code_seg(&self) -> u16 {
        unsafe { self.frame.f32.cs as u16 }
    }

    /// Get flags
    pub fn flags(&self) -> u64 {
        unsafe { self.frame.f32.eflags as u64 }
    }

    /// Get stack pointer
    pub fn sp(&self) -> u64 {
        unsafe { self.frame.f32.esp as u64 }
    }

    /// Get stack segment
    pub fn stack_seg(&self) -> u16 {
        unsafe { self.frame.f32.ss as u16 }
    }
}

impl core::fmt::Debug for Regs {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(f, "INT: {:#04x}  ERR: {:#010x}", self.int_num, self.err_code)?;
        writeln!(f, "IP:  {:#010x}  CS: {:#06x}  FL: {:#010x}", self.ip(), self.code_seg(), self.flags())?;
        writeln!(f, "SP:  {:#010x}  SS: {:#06x}", self.sp(), self.stack_seg())?;
        writeln!(f, "RAX: {:#018x}  RBX: {:#018x}", self.rax, self.rbx)?;
        writeln!(f, "RCX: {:#018x}  RDX: {:#018x}", self.rcx, self.rdx)?;
        writeln!(f, "RSI: {:#018x}  RDI: {:#018x}", self.rsi, self.rdi)?;
        writeln!(f, "RBP: {:#018x}  R8:  {:#018x}", self.rbp, self.r8)?;
        writeln!(f, "R9:  {:#018x}  R10: {:#018x}", self.r9, self.r10)?;
        writeln!(f, "R11: {:#018x}  R12: {:#018x}", self.r11, self.r12)?;
        writeln!(f, "R13: {:#018x}  R14: {:#018x}", self.r13, self.r14)?;
        writeln!(f, "R15: {:#018x}", self.r15)?;
        write!(f, "DS: {:#06x}  ES: {:#06x}  FS: {:#06x}  GS: {:#06x}",
               self.ds as u16, self.es as u16, self.fs as u16, self.gs as u16)
    }
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
