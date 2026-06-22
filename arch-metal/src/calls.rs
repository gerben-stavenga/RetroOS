//! Ring-1 → ring-0 arch interface: the calls the kernel makes *into* the arch
//! layer. On hardware each traps to ring 0 via `int 0x80` (serviced by the
//! handlers in `traps.rs`); a software-interpreter backend would implement the
//! same set of functions as direct calls. Either way this is the kernel-facing
//! arch API surface — the kernel layer never issues `int 0x80` itself.

/// Resume user code via arch `EXECUTE` (INT 0x80) and return the next
/// kernel-visible event. The arch→kernel boundary is `(eax, edx)` =
/// `(event, extra)`; this function decodes it into `KernelEvent` right away
/// so the event loop never sees raw tag numbers.
#[inline(never)]
pub fn do_arch_execute() -> crate::monitor::KernelEvent {
    let event: u32;
    let extra: u32;
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inout("eax") crate::arch_call::EXECUTE as u32 => event,
            out("edx") extra,
            out("ecx") _,
            out("ebx") _,
            out("edi") _,
        );
    }
    crate::monitor::KernelEvent::decode(event, extra)
}

/// Switch threads: swap live state with pointed-to state.
/// On entry: ptrs hold incoming state. On exit: ptrs hold saved outgoing state.
/// hash_ptr: null = no hashing. Non-null: on entry = expected hash (0=don't check),
/// on exit = old address space hash.
pub fn arch_switch_to(
    vcpu: &mut crate::Vcpu,
    hash_ptr: *mut u64,
    fx_ptr: *mut crate::FxState,
) {
    // The arch call still takes two separate pointers (regs in EDX, page-table
    // root in ECX); the Vcpu bundle is purely kernel-side, so we hand the
    // handler `&mut vcpu.regs` and `&mut vcpu.space` exactly as before.
    // LLVM reserves ESI/EDI for its own use in inline asm on x86, so we
    // can't name them directly. Stash fx_ptr in ESI around the int 0x80.
    unsafe {
        core::arch::asm!(
            "xchg esi, {fx}",
            "int 0x80",
            "xchg esi, {fx}",
            fx = inout(reg) fx_ptr as u32 => _,
            in("eax") crate::arch_call::SWITCH_TO as u32,
            in("edx") &mut vcpu.regs as *mut _ as u32,
            in("ecx") &mut vcpu.space as *mut _ as u32,
            in("ebx") hash_ptr as u32,
        );
    }
}

/// COW fork the current address space. Fills child root.
/// Caller must save parent root after (fork modifies entries for COW).
pub fn arch_user_fork(child_root: &mut super::RootPageTable) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch_call::FORK as u32,
            in("edx") child_root as *mut _ as u32,
        );
    }
}

pub fn arch_user_clean() {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch_call::CLEAN as u32,
        );
    }
}



/// Set page permissions for a range. flags: bit 0 = writable, bit 1 = executable.
pub fn arch_set_page_flags(start_vpage: usize, count: usize, writable: bool, executable: bool) {
    let flags = (writable as u32) | ((executable as u32) << 1);
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch_call::SET_PAGE_FLAGS as u32,
            in("edx") start_vpage as u32,
            in("ecx") count as u32,
            in("ebx") flags,
        );
    }
}

/// Map first 1MB user-accessible for VM86.
pub fn arch_map_low_mem() {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch_call::MAP_LOW_MEM as u32,
        );
    }
}

/// Map this process's VGA color-text aperture onto the shared text screen.
pub fn arch_map_vga_text_aperture() {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch_call::MAP_VGA_TEXT_APERTURE as u32,
        );
    }
}

/// Copy page table entries from src to dst.
pub fn arch_copy_page_entries(src_vpage: usize, dst_vpage: usize, count: usize) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch_call::COPY_PAGE_ENTRIES as u32,
            in("edx") src_vpage as u32,
            in("ecx") dst_vpage as u32,
            in("ebx") count as u32,
        );
    }
}

pub fn arch_swap_page_entries(a_vpage: usize, b_vpage: usize, count: usize) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch_call::SWAP_PAGE_ENTRIES as u32,
            in("edx") a_vpage as u32,
            in("ecx") b_vpage as u32,
            in("ebx") count as u32,
        );
    }
}

/// Clear page entries to absent (enables demand paging on next access).
pub fn arch_unmap_range(base_page: usize, count: usize) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch_call::UNMAP_RANGE as u32,
            in("edx") base_page as u32,
            in("ecx") count as u32,
        );
    }
}

/// Free physical pages and restore identity-mapped read-only entries.
pub fn arch_free_range(base_page: usize, count: usize) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch_call::FREE_RANGE as u32,
            in("edx") base_page as u32,
            in("ecx") count as u32,
        );
    }
}




/// Load the LDT: write base+limit into GDT[12] and execute LLDT. Takes the LDT
/// as a slice so base and limit travel together; the metal backend splits it
/// into the `edx`/`ecx` register pair for the trap (the kernel address fits
/// `edx` losslessly), while a hosted backend keeps the full fat pointer.
pub fn arch_load_ldt(ldt: &[u64]) {
    let base = ldt.as_ptr();
    let limit = (core::mem::size_of_val(ldt) - 1) as u32;
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch_call::LOAD_LDT as u32,
            in("edx") base as usize as u32,
            in("ecx") limit,
        );
    }
}

/// Map a range of physical pages into user virtual space.
pub fn arch_map_phys_range(vpage_start: usize, num_pages: usize, ppage_start: u64, flags: u64) {
    unsafe {
        // EBX holds only the low 32 bits of the physical page; pages above 4 GB
        // (an NVMe BAR placed >4 GB by firmware on a wide-MAXPHYADDR CPU) need
        // the high half in ESI (arg3, otherwise unused here). ESI is LLVM-
        // reserved, so save/load/restore it around the trap.
        core::arch::asm!(
            "push esi",
            "mov esi, {hi:e}",
            "int 0x80",
            "pop esi",
            hi = in(reg) (ppage_start >> 32) as u32,
            in("eax") crate::arch_call::MAP_PHYS_RANGE as u32,
            in("edx") vpage_start as u32,
            in("ecx") num_pages as u32,
            in("ebx") ppage_start as u32,
            in("edi") flags as u32,
        );
    }
}

/// Allocate `num_pages` physically contiguous, ISA-DMA-safe pages
/// (< 16 MB, not crossing a `1 << boundary_log2` boundary). Returns the
/// starting physical page number, or 0 on failure.
#[allow(dead_code)]
pub fn arch_alloc_phys_contig(num_pages: usize, boundary_log2: u32) -> u64 {
    let r: u32;
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inlateout("eax") crate::arch_call::ALLOC_PHYS_CONTIG as u32 => r,
            in("edx") num_pages as u32,
            in("ecx") boundary_log2,
        );
    }
    r as u64
}

/// Free a contiguous run previously returned by `arch_alloc_phys_contig`.
#[allow(dead_code)]
pub fn arch_free_phys_contig(start_page: u64, num_pages: usize) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch_call::FREE_PHYS_CONTIG as u32,
            in("edx") start_page as u32,
            in("ecx") num_pages as u32,
        );
    }
}

/// Re-arm (re-unmask) an IRQ line that `handle_irq` left masked because
/// its ack is deferred to the guest. Call once the guest's device-ack
/// has passed through, so the next interrupt on that line can fire.
pub fn arch_rearm_irq(line: u8) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch_call::REARM_IRQ as u32,
            in("edx") line as u32,
        );
    }
}

/// Physical page of DMA channel `ch`'s permanent ISA-DMA buffer (0 = none).
pub fn arch_dma_channel_buf(ch: usize) -> u64 {
    let r: u32;
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inlateout("eax") crate::arch_call::DMA_CHANNEL_BUF as u32 => r,
            in("edx") ch as u32,
        );
    }
    r as u64
}

/// Replace `count` user pages at `vpage` with fresh anonymous RW frames.
pub fn arch_map_fresh_range(vpage: usize, count: usize) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch_call::MAP_FRESH_RANGE as u32,
            in("edx") vpage as u32,
            in("ecx") count as u32,
        );
    }
}

/// Set a per-thread TLS GDT entry. Returns the GDT index or -1 on error.
pub fn arch_set_tls_entry(index: i32, base: u32, limit: u32, limit_in_pages: bool) -> i32 {
    let result: u32;
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inout("eax") crate::arch_call::SET_TLS_ENTRY as u32 => result,
            in("edx") index as u32,
            in("ecx") base,
            in("ebx") limit,
            in("edi") limit_in_pages as u32,
        );
    }
    result as i32
}

/// Free user pages in current address space (arch CLEAN call).
pub fn arch_free_user_pages() {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch_call::CLEAN as u32,
        );
    }
}

/// Arm hardware write-watchpoints at up to two addresses (`addr1==0`/`None`
/// disables the second/both). The ring-0 handler programs the debug registers
/// so a guest write to a watched address raises `#DB`.
pub fn arch_set_debug_watch(addrs: Option<(u32, u32)>) {
    let (count, addr0, addr1) = match addrs {
        Some((a0, a1)) if a1 != 0 => (2u32, a0, a1),
        Some((a0, _)) => (1u32, a0, 0),
        None => (0u32, 0, 0),
    };
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch_call::SET_DEBUG_WATCH as u32,
            in("ebx") count,
            in("edx") addr0,
            in("ecx") addr1,
        );
    }
}
