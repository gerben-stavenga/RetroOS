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
        /* KEEP the multiboot header: it is read externally by a multiboot
         * loader (GRUB), never referenced by kernel code, so rust-lld's
         * --gc-sections would otherwise collect it. Must stay first / in the
         * first 8 KiB for GRUB to find it. */
        KEEP(*(.multiboot))
        *(.text .text.*)
        KEEP(*(.note*))
    }

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

    .bss ALIGN(4K) : {
        *(.bss .bss.*)
        *(COMMON)
        /* ARCH_STACK lives at the END of .bss, preceded by a guard page that
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
    }
    _end = .;

    /DISCARD/ : {
        *(.eh_frame)
        *(.comment)
    }
}
