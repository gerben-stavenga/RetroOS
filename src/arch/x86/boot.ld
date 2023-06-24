SECTIONS
{
  . = 0x7C00;
  .text : { *(.text) }
  .rodata : { *(.rodata) }
  .data : { *(.data) }
  _edata = .;
  .bss : { *(.bss) }
  _end = .;
}
