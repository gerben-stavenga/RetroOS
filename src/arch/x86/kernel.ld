SECTIONS
{
  . = 0xE0000000;
  .text ALIGN(4K) : { 
    *(.text) 
    KEEP(*(.note*))
  }
  .rodata : { *(.rodata) }
  .data ALIGN(4K) : { *(.data) }
  _edata = .;
  .bss : { *(.bss) }
  _end = .;
}
