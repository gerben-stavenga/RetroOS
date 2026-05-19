/* RLOADER — pure-PM flat loader. Linked as one contiguous image, then
   `objcopy -O binary` → RLOADER.BIN. Self-relocating is preferred long
   term (run at any base); for the first bring-up we link at a fixed base
   the stub honours when it copies the .BIN in. Keep a single load region
   so the flat .BIN == [0, _end - _base). */
ENTRY(_start)

SECTIONS
{
    /* Base 0: the stub creates a 32-bit code/data selector whose BASE is
       the linear address of the buffer RLOADER was read into, so all of
       RLOADER's addresses are selector-relative offsets from 0 (DJGPP-
       style selector-base trick). _start must be at offset 0. */
    . = 0;
    __rloader_base = .;

    .text   : { *(.text._start) *(.text .text.*) }
    .rodata : { *(.rodata .rodata.*) }
    .data   : { *(.data .data.*) }

    __bss_start = .;
    .bss    : { *(.bss .bss.*) *(COMMON) }
    __bss_end = .;
    __rloader_end = .;

    /DISCARD/ : { *(.eh_frame) *(.comment) *(.note*) }
}
