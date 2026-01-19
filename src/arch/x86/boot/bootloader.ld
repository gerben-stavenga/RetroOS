SECTIONS
{
  regs = 0x7C00 - 32;
  . = 0x7C00;
  .boot : {
    *(.boot)
    . = 0x1FE;
    SHORT(0xAA55)
  }
  .text : { 
    *(.text*)
    *(.group*)
    KEEP(*(.note*))
  }
  .rodata : { *(.rodata*) }
  .data ALIGN(4K) : { *(.data*) }
  _edata = .;
  .bss : { *(.bss*) }
  _end = .;
}
