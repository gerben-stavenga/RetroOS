/* RetroOS Rust Bootloader Linker Script */
/* Loaded at 0x7C00 by BIOS, MBR in first 512 bytes */

ENTRY(_start)

SECTIONS
{
    /* BIOS register struct at 32 bytes below MBR */
    regs = 0x7C00 - 32;

    . = 0x7C00;

    /* MBR section - must fit in 512 bytes with partition table + signature */
    .boot : {
        *(.boot)
        . = 0x1BE;
        FILL(0x00000000)
        /* Partition entry 1: TAR filesystem */
        BYTE(0x80)                              /* status: active */
        BYTE(0) BYTE(0) BYTE(0)                 /* CHS first (unused, LBA mode) */
        BYTE(0xDA)                              /* type: non-FS data */
        BYTE(0) BYTE(0) BYTE(0)                 /* CHS last (unused) */
        LONG((_edata - _start + 511) / 512)     /* LBA start = bootloader sectors */
        LONG(0)                                 /* size in sectors */
        /* Entries 2-4: zeroed by fill to 0x1FE */
        . = 0x1FE;
        SHORT(0xAA55)  /* MBR boot signature */
    }

    /* Code section - starts at 0x7E00 (after MBR) */
    /* full_boot_main MUST be first - it's loaded from disk to 0x7E00 */
    .text : {
        *(.text.full_boot_main)
        *(.text .text.*)
        *(.group*)
    }

    /* Read-only data */
    .rodata : {
        *(.rodata .rodata.*)
    }

    /* Initialized data (4K aligned for potential page alignment) */
    .data ALIGN(4K) : {
        *(.data .data.*)
    }

    _edata = .;

    /* Uninitialized data */
    .bss : {
        *(.bss .bss.*)
    }

    _end = .;

    /* Discard unnecessary sections */
    /DISCARD/ : {
        *(.eh_frame)
        *(.comment)
    }
}
