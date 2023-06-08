section .text

align 16
_int_vector:
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

extern handler

wrapper_without_error_code:
    push qword [rsp]
    mov qword [rsp + 8], 0
wrapper_with_error_code:
    and qword [rsp], 0xFF
    push rax
    push rbx
    push rcx
    push rdx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    push fs
    push gs

    cld
    mov rdi, rsp
    call _isr_handler

    pop gs
    pop fs
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rdx
    pop rcx
    pop rbx
    pop rax
    add rsp, 16
    iret