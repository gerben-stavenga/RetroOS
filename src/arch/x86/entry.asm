section .text
[bits 32]
    extern kmain ; coded in c
global _start
_start:
    ; stack contains drive number
    jmp kmain

align 8
global int_vector
int_vector:
%assign i 0
%rep 256
align 8
%if i >= 128
    push (i - 256)
%else
    push i
%endif
%if i == 8 || i == 10 || i == 11 || i == 12 || i == 13 || i == 14 || i == 17 || i == 21 || i == 29 || i == 30
    jmp wrapper_with_error_code
%else
    jmp wrapper_without_error_code
%endif
%assign i (i + 1)
%endrep

extern isr_handler

wrapper_without_error_code:
    sub esp, 4
    push ebp
    mov ebp, esp
    push eax
    mov eax, [ebp + 8]
    mov [ebp + 4], eax
    mov dword [ebp + 8], 0
    pop eax
    pop ebp
wrapper_with_error_code:
    pusha
    push ds
    push es
    push fs
    push gs

    mov eax, 0x10
    mov ds, eax
    mov es, eax
    mov fs, eax
    mov gs, eax

    mov ebp, esp
    and dword [ebp + 48], 0xFF

    cld
    push ebp
    call isr_handler
    pop ebp

    pop gs
    pop fs
    pop es
    pop ds
    popa
    add esp, 8
    iret
