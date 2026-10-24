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
     * Page alignment also accommodates CPU-local page-table storage. */
    .tdata ALIGN(4K) : {
        TLS_TEMPLATE = .;
        *(.tdata .tdata.*)
    }
    .tbss : {
        *(.tbss .tbss.*)
    }
    TLS_ALIGN = MAX(ALIGNOF(.tdata), ALIGNOF(.tbss));
    TLS_FILE_SIZE = SIZEOF(.tdata);
    TLS_SIZE = ALIGN(ADDR(.tbss) + SIZEOF(.tbss) - TLS_TEMPLATE, TLS_ALIGN);

    .bss ALIGN(128K) (NOLOAD) : {
        *(.bss .bss.*)
        *(COMMON)
        /* The BSP needs no allocator. AP copies will be dynamically allocated
         * using the same TLS_SIZE/TLS_ALIGN contract. The word at TP is self. */
        . = ALIGN(TLS_ALIGN);
        BOOT_TLS_BASE = .;
        . += TLS_SIZE;
        BOOT_TLS_TP = .;
        . += 8; /* self pointer, espfix stack window */
        /* ARCH_STACK is preceded by a guard page that
         * boot.rs unmaps. Its overflow can't be reported — #PF would be
         * delivered on the overflowed stack itself — but the unmapped guard
         * turns silent corruption into a triple fault, easy to diagnose.
         * KERNEL_STACK is NOT here; see .kstack above.
         * Addresses are linker symbols — Rust references them via extern. */
        . = ALIGN(4K);
        /* espfix invariant (see GDT_ESPFIX_SS in arch-metal/descriptors.rs):
         * ARCH_STACK is the ring-0 trap stack (TSS.sp0) — 64K-ALIGN it so
         * the whole 16 KB stack sits inside one 64K segment window and every
         * ESP's low 16 bits equal its offset from the window base, letting
         * the exit path truncate ESP against the aliased SS. The guard page
         * stays directly below the aligned base. */
        . += 0x1000;
        . = ALIGN(64K);
        ARCH_STACK_GUARD   = . - 0x1000;
        ARCH_STACK         = .;     . += 0x4000;   /* 16 KB, 64K-aligned */
        ARCH_STACK_TOP     = .;
        KERNEL_CORE_END = .;
        /* Keep this unique input section LAST, outside the .bss.* wildcard.
         * NOLOAD reserves RAM in the ELF without storing zero bytes on disk. */
        . = ALIGN(128K);
        BOOT_POOL_START = .;
        KEEP(*(.boot_pool))
        BOOT_POOL_END = .;
    }
    _end = .;
    ASSERT(KERNEL_CORE_END - KERNEL_BASE <= 0x220000,
           "kernel excluding boot pool exceeds 2.125 MiB")
    ASSERT(BOOT_POOL_END == _end, "boot pool must be last in BSS")
    ASSERT(_end - KERNEL_BASE + KERNEL_PHYS <= 4M - 128K,
           "kernel and boot pool must leave 128 KiB below physical 4 MiB")

    /DISCARD/ : {
        *(.eh_frame)
        *(.comment)
    }
}
