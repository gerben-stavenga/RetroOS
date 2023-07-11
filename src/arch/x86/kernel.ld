SECTIONS
{
  . = 0xE0000000;
  .text : { *(.text) }
  .rodata : { *(.rodata) }
  .data : { *(.data) }
  _edata = .;
  .bss : { *(.bss) }
  _end = .;
}
