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
        *(.multiboot)
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

    .data ALIGN(4K) : {
        *(.data .data.*)
    }
    _edata = .;

    .bss ALIGN(4K) : {
        *(.bss .bss.*)
        *(COMMON)
        /* Stacks live at the END of .bss, each preceded by a guard page
         * that boot.rs unmaps so overflow page-faults instead of silently
         * corrupting adjacent memory. KERNEL_STACK overflow is caught
         * cleanly by traps.rs (handler runs on ARCH_STACK). ARCH_STACK
         * overflow can't be reported — #PF would be delivered on the
         * overflowed stack itself — but the unmapped guard turns silent
         * corruption into a triple fault, which is easy to diagnose.
         * Addresses are linker symbols — Rust references them via extern. */
        . = ALIGN(4K);
        KERNEL_STACK_GUARD = .;     . += 0x1000;   /* 4 KB */
        KERNEL_STACK       = .;     . += 0x10000;  /* 64 KB */
        KERNEL_STACK_TOP   = .;
        . = ALIGN(4K);
        ARCH_STACK_GUARD   = .;     . += 0x1000;   /* 4 KB */
        ARCH_STACK         = .;     . += 0x4000;   /* 16 KB */
        ARCH_STACK_TOP     = .;
    }
    _end = .;

    /DISCARD/ : {
        *(.eh_frame)
        *(.comment)
    }
}
