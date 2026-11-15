//! Ring-1 → ring-0 arch interface: the calls the kernel makes *into* the arch
//! layer. On hardware each traps to ring 0 via `int 0x80` (serviced by the
//! handlers in `traps.rs`); a software-interpreter backend would implement the
//! same set of functions as direct calls. Either way this is the kernel-facing
//! arch API surface — the kernel layer never issues `int 0x80` itself.

/// Resume user code via arch `EXECUTE` (INT 0x80) and return the raw event
/// words. Decoding stays outside this wrapper so its cost can be measured
/// independently from the privilege transition and guest run.
#[inline(never)]
pub fn do_arch_execute_raw(max_ns: u64) -> (u32, u64) {
    let event: u32;
    let extra: u32;
    let extra_high: u32;
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inout("eax") crate::arch_call::EXECUTE as u32 => event,
            inout("edx") max_ns as u32 => extra,
            inout("ecx") (max_ns >> 32) as u32 => extra_high,
            out("ebx") _,
            out("edi") _,
        );
    }
    (event, u64::from(extra) | (u64::from(extra_high) << 32))
}

pub fn arch_replace_interrupt_handlers(vector: u8, mut handlers: arch_abi::InterruptHandlers) -> arch_abi::InterruptHandlers {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch_call::REPLACE_INTERRUPT_HANDLERS as u32,
            in("edx") &mut handlers as *mut arch_abi::InterruptHandlers as u32,
            in("ecx") u32::from(vector),
        );
    }
    handlers
}

/// Exchange the active address space with `space`.
pub fn arch_activate(space: &mut super::RootPageTable) {
    unsafe {
        core::arch::asm!("int 0x80",
            in("eax") crate::arch_call::ACTIVATE as u32,
            in("edx") space as *mut super::RootPageTable as u32,
        );
    }
}

/// Record the current page-table hash and optionally compare it to a snapshot.
pub fn arch_check_address_space(mut expected: u64) -> u64 {
    unsafe {
        core::arch::asm!("int 0x80",
            in("eax") crate::arch_call::CHECK_ADDRESS_SPACE as u32,
            in("edx") &mut expected as *mut u64 as u32,
        );
    }
    expected
}

pub fn arch_switch_fx(fx: &mut crate::FxState) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch_call::SWITCH_FX as u32,
            in("edx") fx as *mut _ as u32,
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

/// Heap release hook, usable during ring-0 boot and ring-1 kernel execution.
/// Does not allocate or call back into the heap.
pub fn release_heap_pages(addr: usize, bytes: usize) {
    let cs: u16;
    unsafe { core::arch::asm!("mov {0:x}, cs", out(reg) cs, options(nomem, nostack, preserves_flags)); }
    if cs & 3 == 0 {
        crate::paging2::release_heap_pages(addr, bytes);
    } else {
        unsafe {
            core::arch::asm!(
                "int 0x80",
                in("eax") crate::arch_call::RELEASE_HEAP as u32,
                in("edx") addr as u32,
                in("ecx") bytes as u32,
            );
        }
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
pub fn arch_map_kernel_physical(vpage_start: usize, num_pages: usize, ppage_start: u64, flags: u64) {
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
            in("eax") crate::arch_call::MAP_KERNEL_PHYSICAL as u32,
            in("edx") vpage_start as u32,
            in("ecx") num_pages as u32,
            in("ebx") ppage_start as u32,
            in("edi") flags as u32,
        );
    }
}

/// Re-arm (re-unmask) an IRQ line that `handle_irq` left masked because
/// its ack is deferred to the guest. Call once the guest's device-ack
/// has passed through, so the next interrupt on that line can fire.
pub fn arch_isa_unmask_irq(line: u8) {
    unsafe {
        core::arch::asm!(
            "int 0x80",
            in("eax") crate::arch_call::ISA_UNMASK_IRQ as u32,
            in("edx") line as u32,
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

/// Wait for an interruption, bounded by this call's duration.
pub fn arch_idle(max_ns: u64) {
    unsafe { core::arch::asm!("int 0x80", in("eax") crate::arch_call::IDLE as u32,
        in("edx") max_ns as u32, in("ecx") (max_ns >> 32) as u32); }
}

/// Synchronize this core's privileged mappings with platform updates.
pub fn arch_refresh_kernel_mappings() {
    unsafe { core::arch::asm!("int 0x80", in("eax") crate::arch_call::REFRESH_KERNEL as u32); }
}
