/* Linker script for 64-bit user programs */

ENTRY(_start)
OUTPUT_FORMAT(elf64-x86-64)

SECTIONS
{
    /* User programs start at 64KB (after null page protection) */
    . = 0x10000;

    .text : {
        *(.text .text.*)
    }

    .rodata : {
        *(.rodata .rodata.*)
    }

    .data : {
        *(.data .data.*)
    }

    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    }

    /* Discard unwanted sections */
    /DISCARD/ : {
        *(.eh_frame)
        *(.note.*)
        *(.comment)
    }
}
