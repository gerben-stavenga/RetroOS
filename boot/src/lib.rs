//! RetroOS Rust Bootloader
//!
//! This is the 32-bit protected mode bootloader that loads the kernel
//! from a TAR filesystem and jumps to it.

#![no_std]
#![no_main]

use core::panic::PanicInfo;
use lib::{elf::Elf, md5, print, println, tar::TarHeader, vga};

/// Low memory buffer for BIOS disk reads (must be below 640KB)
/// Placed at 320KB to avoid bootloader which is at 0x7C00-~0x40000
const LOW_BUFFER: usize = 0x50000;
const CHUNK_SIZE: usize = 0x10000; // 64KB chunks

/// High memory buffer for ELF (above 1MB, accessible via A20)
const ELF_HIGH_BUFFER: usize = 0x100000;

/// BIOS register structure for interrupt calls
/// Must match the assembly REGS struct layout
#[repr(C)]
pub struct BiosRegs {
    pub ax: u32,
    pub bx: u32,
    pub cx: u32,
    pub dx: u32,
    pub si: u32,
    pub di: u32,
    pub bp: u32,
    pub ds: u16,
    pub es: u16,
}

/// Memory map entry from BIOS INT 0x15 E820
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct MMapEntry {
    pub base: u64,
    pub length: u64,
    pub typ: u32,
    pub acpi: u32,
}

/// Boot data passed to kernel
#[repr(C)]
pub struct BootData {
    pub kernel: *const u8,
    pub start_sector: u32,
    pub cursor_pos: u32,
    pub mmap_count: i32,
    pub mmap_entries: [MMapEntry; 32],
}

unsafe extern "C" {
    /// Generate a real mode interrupt from protected mode
    fn generate_real_interrupt(int_num: u32) -> u32;

    /// BIOS registers at 0x7BE0 (defined in linker script)
    static mut regs: BiosRegs;

    /// Linker symbols
    static _start: u8;
    static _edata: u8;
    static _end: u8;
}

/// MBR entry point - must fit in first 512 bytes!
/// Loads the rest of the bootloader from disk, then jumps to full_boot_main.
///
/// # Arguments (fastcall convention)
/// * `nsectors_bytes` - Number of bytes to load (in ECX)
/// * `drive` - BIOS drive number (in EDX)
#[unsafe(no_mangle)]
#[unsafe(link_section = ".boot")]
pub extern "fastcall" fn boot_main(nsectors_bytes: u32, drive: u32) -> ! {
    // Calculate number of sectors to load
    let nsectors = (nsectors_bytes + 511) / 512;

    // Load rest of bootloader from disk sector 1 to 0x7E00
    let success = read_disk(drive, 1, nsectors, 0x7E00 as *mut u8);

    if success {
        full_boot_main(nsectors_bytes, drive);
    } else {
        loop {
            unsafe { core::arch::asm!("hlt"); }
        }
    }
}

/// Read sectors from disk (general version for TAR reading)
#[inline(always)]
fn read_disk(drive: u32, lba: u32, count: u32, buffer: *mut u8) -> bool {
    const MAX_SECTORS: u32 = 100;
    let mut lba = lba;
    let mut count = count;
    let mut segment = (buffer as u32) >> 4;
    let offset = (buffer as u32) & 0xF;

    while count > 0 {
        let num_sectors = if count > MAX_SECTORS { MAX_SECTORS } else { count };

        #[repr(C, packed)]
        struct Dap {
            size: u8,
            zero: u8,
            count: u16,
            offset: u16,
            segment: u16,
            lba_low: u32,
            lba_high: u32,
        }

        let dap = Dap {
            size: 16,
            zero: 0,
            count: num_sectors as u16,
            offset: offset as u16,
            segment: segment as u16,
            lba_low: lba,
            lba_high: 0,
        };

        unsafe {
            regs.ax = 0x4200;
            regs.dx = drive;
            regs.ds = 0;
            regs.si = &dap as *const _ as u32;

            let flags = generate_real_interrupt(0x13);
            if (flags & 1) != 0 {
                return false;
            }
        }

        segment += num_sectors * (512 / 16);
        lba += num_sectors;
        count -= num_sectors;
    }
    true
}

/// Check if A20 line is enabled
fn check_a20() -> bool {
    let tmp: u32 = 0xDEADBEEF;
    let tmp_addr = &tmp as *const u32 as usize;
    let aliased_addr = tmp_addr ^ 0x100000;
    let aliased = unsafe { *(aliased_addr as *const u32) };
    if tmp != aliased {
        return true;
    }
    let tmp2: u32 = 0xCAFEBABE;
    let tmp2_addr = &tmp2 as *const u32 as usize;
    let aliased_addr2 = tmp2_addr ^ 0x100000;
    let aliased2 = unsafe { *(aliased_addr2 as *const u32) };
    tmp2 != aliased2
}

/// Enable A20 line using BIOS
fn enable_a20() {
    if check_a20() {
        return;
    }
    unsafe {
        regs.ax = 0x2401;
        generate_real_interrupt(0x15);
    }
    if !check_a20() {
        panic!("A20 not enabled");
    }
}

/// Get memory map using BIOS INT 0x15 E820
fn get_memory_map(entries: &mut [MMapEntry]) -> i32 {
    const SMAP_ID: u32 = 0x534D4150; // 'SMAP'
    let mut count = 0i32;

    unsafe {
        regs.es = 0;
        regs.bx = 0;

        while (count as usize) < entries.len() {
            entries[count as usize].acpi = 1;
            regs.ax = 0xE820;
            regs.cx = 24;
            regs.dx = SMAP_ID;
            regs.di = &mut entries[count as usize] as *mut _ as u32;

            let flags = generate_real_interrupt(0x15);

            if regs.ax != SMAP_ID {
                return -1;
            }
            if (flags & 1) != 0 {
                if count == 0 {
                    return -1;
                }
                break;
            }
            if (entries[count as usize].acpi & 1) != 0 {
                count += 1;
            }
            if regs.bx == 0 {
                break;
            }
        }
    }
    count
}

/// Find a file in TAR filesystem and return its LBA and size
fn tar_find_file(drive: u32, fs_lba: u32, filename: &[u8]) -> Option<(u32, usize)> {
    let mut block = 0u32;
    let mut header_buf = [0u8; 512];

    loop {
        if !read_disk(drive, fs_lba + block, 1, header_buf.as_mut_ptr()) {
            return None;
        }
        block += 1;

        let header = unsafe { &*(header_buf.as_ptr() as *const TarHeader) };

        if header.is_end() {
            return None;
        }

        let filesize = header.filesize();

        if header.filename() == filename {
            return Some((fs_lba + block, filesize));
        }

        block += header.data_blocks();
    }
}

/// Read file from TAR filesystem
fn tar_read_file(drive: u32, lba: u32, buffer: *mut u8, size: usize) -> bool {
    let blocks = (size + 511) / 512;
    read_disk(drive, lba, blocks as u32, buffer)
}

fn halt() -> ! {
    loop {
        unsafe { core::arch::asm!("hlt"); }
    }
}

/// Full bootloader entry - this is at 0x7E00, loaded from disk
#[inline(never)]
#[unsafe(link_section = ".text.full_boot_main")]
fn full_boot_main(_nsectors_bytes: u32, drive: u32) -> ! {
    // Zero BSS
    unsafe {
        let bss_start = core::ptr::addr_of!(_edata) as *mut u8;
        let bss_end = core::ptr::addr_of!(_end) as *mut u8;
        let mut p = bss_start;
        while p < bss_end {
            *p = 0;
            p = p.add(1);
        }
    }

    // Clear screen and print banner
    vga::vga().clear();
    println!("\x1b[92mRetroOS Rust Bootloader\x1b[0m");

    // Enable A20 line
    enable_a20();
    println!("A20 enabled");

    // Calculate filesystem LBA (TAR starts after bootloader)
    let fs_lba = unsafe {
        let start = &_start as *const u8 as u32;
        let edata = &_edata as *const u8 as u32;
        (edata - start + 511) / 512
    };

    // Find MD5 checksum file
    let md5_path = b"kernel.elf.md5";
    let (md5_lba, md5_size) = match tar_find_file(drive, fs_lba, md5_path) {
        Some(result) => result,
        None => {
            println!("Error: kernel.elf.md5 not found");
            halt();
        }
    };
    if md5_size != 16 {
        println!("Error: invalid md5 file size");
        halt();
    }

    // Read expected MD5 (need 512-byte buffer since TAR reads full blocks)
    let mut md5_block = [0u8; 512];
    if !tar_read_file(drive, md5_lba, md5_block.as_mut_ptr(), 16) {
        println!("Error: failed to read md5 file");
        halt();
    }
    let expected_md5: [u8; 16] = md5_block[..16].try_into().unwrap();

    // Find kernel ELF
    let kernel_path = b"kernel.elf";
    let (kernel_lba, kernel_size) = match tar_find_file(drive, fs_lba, kernel_path) {
        Some(result) => result,
        None => {
            println!("Error: kernel.elf not found");
            halt();
        }
    };

    println!("Loading kernel size {:#x}", kernel_size);

    // Load ELF to high memory in chunks (BIOS can only read to <1MB)
    let low_buf = LOW_BUFFER as *mut u8;
    let high_buf = ELF_HIGH_BUFFER as *mut u8;
    let mut offset = 0usize;

    while offset < kernel_size {
        let chunk = (kernel_size - offset).min(CHUNK_SIZE);
        let sectors = ((chunk + 511) / 512) as u32;
        let lba = kernel_lba + (offset as u32 / 512);

        // Read to low memory via BIOS
        if !read_disk(drive, lba, sectors, low_buf) {
            println!("Error: failed to read kernel");
            halt();
        }

        // Copy to high memory (CPU can access above 1MB with A20 enabled)
        unsafe {
            core::ptr::copy_nonoverlapping(low_buf, high_buf.add(offset), chunk);
        }

        offset += chunk;
    }

    // Verify MD5 from high memory copy
    let elf_slice = unsafe { core::slice::from_raw_parts(high_buf, kernel_size) };

    let mut computed_md5 = [0u8; 16];
    md5::compute(elf_slice, &mut computed_md5);

    if expected_md5 != computed_md5 {
        println!("Error: kernel MD5 mismatch!");
        halt();
    }
    println!("MD5 verified");

    // Parse ELF from high memory
    let elf = match Elf::parse(elf_slice) {
        Ok(e) => e,
        Err(_) => {
            println!("Error: invalid ELF");
            halt();
        }
    };

    // Derive kernel base from lowest segment vaddr (no hardcoded coupling)
    let kernel_base = elf.segments().map(|s| s.vaddr).min().unwrap_or(0) & !0xFFF;

    // Calculate kernel physical base (page-aligned after ELF buffer in high memory)
    let kernel_buffer = ((ELF_HIGH_BUFFER + kernel_size + 0xFFF) & !0xFFF) as *mut u8;

    println!("Loading segments at {:#x}", kernel_buffer as u32);

    // Load ELF segments to their final physical addresses
    for seg in elf.segments() {
        let phys_addr = kernel_buffer as usize + seg.vaddr - kernel_base;
        if let Some(data) = seg.data {
            unsafe {
                core::ptr::copy_nonoverlapping(data.as_ptr(), phys_addr as *mut u8, data.len());
            }
            // Zero BSS
            if seg.memsz > data.len() {
                unsafe {
                    core::ptr::write_bytes((phys_addr + data.len()) as *mut u8, 0, seg.memsz - data.len());
                }
            }
        } else if seg.memsz > 0 {
            unsafe {
                core::ptr::write_bytes(phys_addr as *mut u8, 0, seg.memsz);
            }
        }
    }

    // Get memory map
    let mut boot_data = BootData {
        kernel: kernel_buffer,
        start_sector: fs_lba,
        cursor_pos: 0,
        mmap_count: 0,
        mmap_entries: [MMapEntry { base: 0, length: 0, typ: 0, acpi: 0 }; 32],
    };
    boot_data.mmap_count = get_memory_map(&mut boot_data.mmap_entries);

    println!("Starting kernel...");

    // Jump to kernel entry (adjusted for physical address)
    let entry_phys = kernel_buffer as u32 + elf.entry() as u32 - kernel_base as u32;
    type KernelEntry = unsafe extern "C" fn(*const BootData) -> !;
    let kernel_entry: KernelEntry = unsafe { core::mem::transmute(entry_phys) };
    unsafe { kernel_entry(&boot_data) };
}

/// Panic handler - required for no_std
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!();
    println!("\x1b[91m!!! PANIC !!!\x1b[0m");

    if let Some(location) = info.location() {
        println!("at {}:{}", location.file(), location.line());
    }

    loop {
        unsafe {
            core::arch::asm!("hlt");
        }
    }
}
