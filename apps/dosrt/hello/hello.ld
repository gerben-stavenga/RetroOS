/* dosrt payload — ordinary 32-bit ELF (RLOADER parses this as ELF). */
ENTRY(_start)

SECTIONS
{
    /* Link base. RLOADER honours p_vaddr/p_paddr from the program headers
       and gives the payload its OWN DPMI-allocated memory + selector
       (INT 31h AX=0501), so this only needs to be a sane, page-aligned
       address that doesn't collide with DOS low memory. */
    . = 0x00400000;

    .text   : { *(.text .text.*) }
    .rodata : { *(.rodata .rodata.*) }
    .data   : { *(.data .data.*) }
    .bss    : { *(.bss .bss.*) *(COMMON) }

    /DISCARD/ : { *(.eh_frame) *(.comment) *(.note*) }
}
