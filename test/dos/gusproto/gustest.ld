/* modplay dosrt payload — position-independent ELF (ET_DYN).
 *
 * Linked at base 0; RLOADER loads it at any DPMI-allocated linear address
 * and applies the `R_386_RELATIVE` fixups from `.rel.dyn` (collected into
 * PT_DYNAMIC, which RLOADER walks). One flat RWX PT_LOAD — the payload
 * runs at CPL 3 with no W^X policy. */
ENTRY(_start)

PHDRS
{
    load    PT_LOAD    FLAGS(7);     /* R+W+X */
    dynamic PT_DYNAMIC FLAGS(6);     /* R+W   */
}

SECTIONS
{
    . = 0;

    .text     : { *(.text._start) *(.text .text.*) } :load
    .rodata   : { *(.rodata .rodata.*) } :load
    .dynsym   : { *(.dynsym) } :load
    .dynstr   : { *(.dynstr) } :load
    .hash     : { *(.hash) } :load
    .rel.dyn  : { *(.rel.dyn) *(.rel.text*) *(.rel.rodata*) *(.rel.data*) } :load
    .dynamic  : { *(.dynamic) } :load :dynamic
    .data.rel.ro : { *(.data.rel.ro*) } :load
    .got      : { *(.got) *(.got.plt) } :load
    .data     : { *(.data .data.*) } :load
    .bss      : { *(.bss .bss.*) *(COMMON) } :load

    /DISCARD/ : {
        *(.eh_frame) *(.comment) *(.note*)
        *(.interp) *(.gnu.version*)
    }
}
