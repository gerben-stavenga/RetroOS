/* RetroOS Rust Kernel Linker Script */
/* Kernel is linked at KERNEL_BASE, loaded at KERNEL_PHYS */

KERNEL_BASE = 0xC0B00000;
KERNEL_PHYS = 0x00100000;

ENTRY(_start)

SECTIONS
{
    . = KERNEL_BASE;
    _kernel_start = .;

    .text ALIGN(4K) : AT(KERNEL_PHYS) {
        /* Keep both Multiboot headers: GRUB reads them externally, never via
         * kernel references, so --gc-sections would otherwise collect them.
         * Both must remain at the start of the image for the GRUB scanners. */
        KEEP(*(.multiboot))
        KEEP(*(.multiboot2))
        /* Boot entry and paging toggle must precede Rust text regardless of
         * the order rustc passes native objects to the linker. */
        KEEP(*(.text.boot))
        *(.text .text.*)
        KEEP(*(.note*))
    }
    ASSERT(toggle_prot_compat >= KERNEL_BASE && toggle_prot_compat_end <= KERNEL_BASE + 4K,
           "paging toggle must remain in the kernel's first physical page")

    . = ALIGN(4K);
    _etext = .;

    .rodata ALIGN(4K) : {
        *(.rodata .rodata.*)
    }

    . = ALIGN(4K);
    _erodata = .;
    _data = .;

    /* KERNEL_STACK sits at the very BOTTOM of the writable region, so the
     * memory it grows down into is .rodata (R-- NX, and CR0.WP is set — see
     * paging2::harden_kernel). A gradual overflow still takes the unmapped
     * guard page; a single frame LARGER than the guard, which a `sub esp,N`
     * with no stack probe can step clean over, lands in read-only memory and
     * faults there instead of silently corrupting .bss. (NOLOAD) keeps the
     * region out of the file image: it is a permission boundary, so the
     * linker already starts a new PT_LOAD here. */
    .kstack (NOLOAD) : ALIGN(4K) {
        KERNEL_STACK_GUARD = .;     . += 0x1000;   /* 4 KB */
        KERNEL_STACK       = .;     . += 0x10000;  /* 64 KB */
        KERNEL_STACK_TOP   = .;
    }

    .data ALIGN(4K) : {
        *(.data .data.*)
    }
    _edata = .;

    /* ELF local-exec TLS template. Runtime copies are separate from the
     * template; GS:0 holds the linked address immediately after each copy.
     * Group page-aligned objects before small fields. Include zero-initialized
     * TLS in the template so initialized and zero fields share the same tail
     * page instead of requiring separate alignment padding. */
    .tdata ALIGN(4K) : {
        TLS_TEMPLATE = .;
        *(SORT_BY_ALIGNMENT(.t[bd]*))
    }
    TLS_ALIGN = ALIGNOF(.tdata);
    TLS_FILE_SIZE = SIZEOF(.tdata);
    TLS_SIZE = ALIGN(SIZEOF(.tdata), TLS_ALIGN);

    .bss ALIGN(4K) (NOLOAD) : {
        *(.bss .bss.*)
        *(COMMON)
        /* The BSP needs no allocator. AP copies will be dynamically allocated
         * using the same TLS_SIZE/TLS_ALIGN contract. The word at TP is self. */
        . = ALIGN(TLS_ALIGN);
        BOOT_TLS_BASE = .;
        . += TLS_SIZE;
        BOOT_TLS_TP = .;
        . += 4; /* self pointer */
        /* ARCH_STACK is preceded by a guard page that
         * boot.rs unmaps. Its overflow can't be reported — #PF would be
         * delivered on the overflowed stack itself — but the unmapped guard
         * turns silent corruption into a triple fault, easy to diagnose.
         * KERNEL_STACK is NOT here; see .kstack above.
         * Addresses are linker symbols — Rust references them via extern. */
        . = ALIGN(4K);
        /* Keep the guard page directly below the trap stack. */
        . += 0x1000;
        ARCH_STACK_GUARD   = . - 0x1000;
        ARCH_STACK         = .;     . += 0x4000;   /* 16 KB */
        ARCH_STACK_TOP     = .;
        KERNEL_CORE_END = .;
        /* Keep this unique input section LAST, outside the .bss.* wildcard.
         * NOLOAD reserves RAM in the ELF without storing zero bytes on disk. */
        . = ALIGN(4K);
        BOOT_POOL_START = .;
        KEEP(*(.boot_pool))
        BOOT_POOL_END = .;
    }
    _end = .;
    /* BSP paging needs seven 4K pages at most (PAE plus the canonical root).
     * Reserve 64K including alignment, and retain boot_mem's 128K transition
     * margin below its 4M identity ceiling. AP allocation is separately bounded
     * by BootMemory::can_allocate; it cannot consume this transition margin. */
    ASSERT(KERNEL_CORE_END - KERNEL_BASE + KERNEL_PHYS + 64K + 128K <= 4M,
           "kernel must leave bootstrap paging space below the identity ceiling")
    ASSERT(BOOT_POOL_END == _end, "boot pool must be last in BSS")
    ASSERT(_end - KERNEL_BASE <= 5M,
           "reserved pool exceeds the existing high kernel mapping")

    /DISCARD/ : {
        *(.eh_frame)
        *(.comment)
    }
}
