KERNEL_ADDRESS EQU 0x1000

section .text
[bits 32]
global _start
_start:
    extern BootLoader
    push edx  ; save the disk drive
    push KERNEL_ADDRESS  ; address to load
    call BootLoader
    add esp, 8
    mov ebx, eax  ; save the cursor position
    jmp KERNEL_ADDRESS

global generate_real_interrupt
generate_real_interrupt:
    mov eax, [esp + 4]
    call far [0x7c2c]
    ret
