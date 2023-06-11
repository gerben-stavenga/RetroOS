section .text
[bits 32]
global _start
_start:
    extern kmain ; coded in c
    jmp kmain

extern isr_handler
wrapper_without_error_code:
    push ebp       ; at the place of where the int_no should be
    mov ebp, esp
    push eax
    xor eax, eax
    xchg eax, [ebp + 4] ; load the int_no from the "error code" location and set the error code to zero
    xchg [ebp], eax  ; store the int_no in the proper stack location and load the old value of ebp into eax
    mov ebp, eax
    pop eax
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

align 64
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

