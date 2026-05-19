/* modplay dosrt payload — ordinary 32-bit ELF (RLOADER parses this). */
ENTRY(_start)

SECTIONS
{
    /* Link base. RLOADER honours p_vaddr/p_paddr and gives the payload
       its own DPMI-allocated memory + selector (AX=0501); just a sane
       page-aligned address clear of DOS low memory. */
    . = 0x00400000;

    .text   : { *(.text._start) *(.text .text.*) }
    .rodata : { *(.rodata .rodata.*) }
    .data   : { *(.data .data.*) }
    .bss    : { *(.bss .bss.*) *(COMMON) }

    /DISCARD/ : { *(.eh_frame) *(.comment) *(.note*) }
}
