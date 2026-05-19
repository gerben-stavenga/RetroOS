/* RLOADER — flat 32-bit image, `objcopy -O binary` → RLOADER.BIN.
   Non-PIC, linked at a fixed nonzero base; the stub builds a selector
   whose base = (buffer_linear - LINK_BASE) so all link addresses
   resolve (DJGPP-style selector-base trick). Single contiguous region
   so the flat .BIN == [0, file_end). rloader_entry must be at file
   offset 0, i.e. link address LINK_BASE. (Entry is NOT named _start:
   dosrt owns _start as the universal app crt0; RLOADER is not an app.) */
ENTRY(rloader_entry)

/* Nonzero so no symbol/static lands at vaddr 0 (LLVM/Rust would treat
   address 0 as a null pointer → miscompile/UB). Must fit a 16-bit far
   offset (the stub's TC MK_FP far-jmp target). Stub does
   selector_base = DS_base + buf_off - 0x1000 and far-jmps sel:0x1000. */
__link_base = 0x1000;

SECTIONS
{
    . = __link_base;

    .text   : { *(.text.rloader_entry) *(.text .text.*) }
    .rodata : { *(.rodata .rodata.*) }
    .data   : { *(.data .data.*) }

    __bss_start = .;
    .bss    : { *(.bss .bss.*) *(COMMON) }
    __bss_end = .;

    /DISCARD/ : { *(.eh_frame) *(.comment) *(.note*) }
}
