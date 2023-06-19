section .text
[bits 32]
global _start
_start:
    push eax  ; push cursor
    push edx  ; push address
    extern SetupPaging
    call SetupPaging
    lea eax, [high_address]
    jmp eax
high_address:
    add esp, 4
    extern kmain ; coded in c
    call kmain

extern isr_handler
entry_wrapper:
    ; stack int handler return address , error code , return stackframe
    ; save remaining registers
    pusha
    push ds
    push es
    push fs
    push gs

    ; set all segments to the kernel value
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
    add esp, 8  ; skip error code and interrupt number
    iret

align 64
global int_vector
int_vector:
%assign i 0
%rep 48
align 8
%if i == 8 || i == 10 || i == 11 || i == 12 || i == 13 || i == 14 || i == 17 || i == 21 || i == 29 || i == 30
    ; error code is already pushed by CPU
%else
    ; push zero error code to make the stack layout uniform
    push 0
%endif
    call entry_wrapper
%assign i (i + 1)
%endrep

global int_0x80
int_0x80:
    push 0
    push int_vector + 0x80 * 8
    jmp entry_wrapper
