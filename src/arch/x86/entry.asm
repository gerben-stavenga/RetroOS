section .text
[bits 32]
global _start
_start:
    call calc_delta
ret_address:
    push eax  ; push delta
    extern EnablePaging
    call EnablePaging  ; this is a relative call and works despite ip not matching the address of
    mov esp, eax  ; EnablePaging returns the new kernel stack in eax
    push ebx  ; pass in cursor position
    extern kmain
    lea eax, [kmain]
    call eax  ; Use absolute address call

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
%rep 49
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

calc_delta:
    mov eax, [esp]
    sub eax, ret_address
    ret