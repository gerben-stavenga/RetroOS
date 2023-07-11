section .text.startup
[bits 32]
global _start
_start:
    mov [_argenv], edi
    push esi  ; argv
    push eax  ; argc
    extern main
    call main
    mov ebx, eax
    mov eax, 1  ; sys_exit
    int 0x80
global terminate
terminate:
    mov eax, 1  ; sys_exit
    mov ebx, [esp + 4]
    int 0x80
section .data
    _argenv dd 0
