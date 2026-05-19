/* dosrt payload — ordinary 32-bit ELF (RLOADER parses this as ELF). */
ENTRY(_start)

SECTIONS
{
    /* Link base. RLOADER honours p_vaddr/p_paddr from the program headers,
       so this only needs to be a sane, page-aligned address that does not
       collide with RLOADER's own load region or DOS low memory. */
    . = 0x00400000;

    .text   : { *(.text .text.*) }
    .rodata : { *(.rodata .rodata.*) }
    .data   : { *(.data .data.*) }
    .bss    : { *(.bss .bss.*) *(COMMON) }

    /DISCARD/ : { *(.eh_frame) *(.comment) *(.note*) }
}
