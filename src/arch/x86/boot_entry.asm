KERNEL_ADDRESS EQU 0x1000

section .text
[bits 32]
global _start
_start:
    extern BootLoader
    push edx
    push KERNEL_ADDRESS  ; address to load
    call BootLoader
    pop edx
    add esp, 4
    jmp KERNEL_ADDRESS

global generate_real_interrupt
generate_real_interrupt:
    mov eax, [esp + 4]
    call far [0x7c2c]
    ret
