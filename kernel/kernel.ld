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
    }
    _end = .;

    /DISCARD/ : {
        *(.eh_frame)
        *(.comment)
    }
}
