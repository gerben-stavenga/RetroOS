section .text.startup
[bits 32]
global _start
_start:
    mov esp, stack_top
    mov [_argenv], edi
    push esi  ; argv
    push eax  ; argc
    extern main
    call main

    mov ebx, eax
    mov eax, 1  ; sys_exit
    int 0x80

section .data
    _argenv dd 0

section .bss
    stack_bottom resb 16384
    stack_top equ stack_bottom + 16384
