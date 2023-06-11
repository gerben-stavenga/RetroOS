section .text
[bits 32]
global _start
_start:
    extern BootLoader
    call BootLoader
