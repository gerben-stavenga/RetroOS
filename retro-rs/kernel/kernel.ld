/* RetroOS Rust Kernel Linker Script */
/* Kernel is loaded by bootloader at arbitrary page-aligned physical address */
/* Entry code (PrepareKernel) adjusts for physical vs linked address */

KERNEL_BASE = 0xC0B00000;

ENTRY(PrepareKernel)

SECTIONS
{
    . = KERNEL_BASE;
    _start = .;

    .text ALIGN(4K) : {
        *(.text .text.*)
        KEEP(*(.note*))
    }

    .rodata ALIGN(4K) : {
        *(.rodata .rodata.*)
    }

    /* Read-only section ends here */
    _data = .;

    .data ALIGN(4K) : {
        *(.data .data.*)
    }
    _edata = .;

    .bss ALIGN(4K) : {
        *(.bss .bss.*)
        *(COMMON)
    }
    _end = .;

    /DISCARD/ : {
        *(.eh_frame)
        *(.comment)
    }
}
