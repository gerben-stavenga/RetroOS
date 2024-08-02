SECTIONS
{
  . = 0xE0000000;
  _start = .;
  .text ALIGN(4K) : { 
    *(.entry)
    *(.text) 
    KEEP(*(.note*))
  }
  .rodata : { *(.rodata) }
  .data ALIGN(4K) : { 
    _data = .;
    *(.data) 
  }
  _edata = .;
  .bss : { *(.bss) }
  _end = .;
}
