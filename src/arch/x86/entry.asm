%ifidn __OUTPUT_FORMAT__,elf
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
%ifidn __OUTPUT_FORMAT__,elf32
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
%ifidn __OUTPUT_FORMAT__,elf64
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
section .text
[bits 32]
global SwitchStack
SwitchStack:
    mov eax, [esp + 8]  ; func arg
    mov esp, [esp + 4]  ; new stack arg
    xor ebp, ebp  ; ensure stack frame ends
    call eax  ; should not return
    ud2

global exit_kernel
exit_kernel:
    cli  ; when called to switch task the regs pointer it's not a proper kernel stack, so no interrupts should occur
    mov esp, [esp + 4]
    jmp exit_interrupt

entry_wrapper_no_error_code:
    push dword [esp]
entry_wrapper:
    ; enlarge 32 bit to match 64 bit entry

    ; stack: int number, error code, iret stack frame (either 32 or 64 bits)
    sub esp, 64  ; Skip padding + extended registers

    ; save remaining registers as zero-extended 64 bit numbers
    push 0
    push edi
    push 0
    push esi
    push 0
    push ebp
    push 0
    push dword [esp + 4 + 12 * 8 + 3 * 4] ; esp as pushed by iret, 4 (upper part pushed above), 11 regs, (int no, err), 3 dwords from interrupt stackframe
    push 0
    push ebx
    push 0
    push edx
    push 0
    push ecx
    push 0   ; upper part of rax
    push eax

    call 0x8:common_entry
    global ret_32
ret_32:
    pop eax
    add esp, 4
    pop ecx
    add esp, 4
    pop edx
    add esp, 4
    pop ebx
    add esp, 12  ; skip esp
    pop ebp
    add esp, 4
    pop esi
    add esp, 4
    pop edi

    add esp, 4 + 64 + 8  ; skip last push 0, skip extended registers, interrupt number and error code
    iret

common_entry:
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

    mov eax, esp

    ; setup a mock stack frame 
    push dword [eax + 20 * 8]  ; push return eip
    push dword [eax + 5 * 8]  ; push old ebp 
    mov ebp, esp

    cld
    push eax  ; save esp value as it is before the instruction pointer is pushed
    extern isr_handler
    call isr_handler  ; does not return
    add esp, 12

    global exit_interrupt
exit_interrupt:
    pop gs
    pop fs
    pop es
    pop ds
    retf

align 64
global int_vector
int_vector:
%assign i 0
%rep 49
align 8 ; The code below is either 4 or 7 bytes long, so aligning to 8 bytes makes for a equal spaced array of handlers
    push i  ; 2 bytes
%if i == 8 || i == 10 || i == 11 || i == 12 || i == 13 || i == 14 || i == 17 || i == 21 || i == 29 || i == 30
    jmp entry_wrapper  ; 2 or 5 bytes
%else
    jmp entry_wrapper_no_error_code  ; 2 or 5 bytes
%endif
%assign i (i + 1)
%endrep

; 64 bit long mode entry code

[bits 64]
target:
    dw 0x8
    dd common_entry
    dd 0

trampoline:
    mov dword [rsp + 4], 0x30
    jmp far [target]

entry_wrapper_no_error_code_64:
    push qword [rsp]
entry_wrapper_64:
    ; stack int_n, error_code
    xchg [rsp], r15     ; r15, error_code  r15=int_n
    push r14
    push r13
    push r12
    push r11
    push r10
    push r9
    push r8
    push rdi
    push rsi
    push rbp
    push qword [rsp + 15 * 8]  ; 11 pushed regs, 1 (int, err), 3 qwords interrupt stack frame
    push rbx
    push rdx
    push rcx
    push rax

    ; patch up error code 
    mov rax, [rsp + 16 * 8]  ; error code
    shl rax, 32
    add rax, r15
    mov [rsp + 16 * 8], rax

    call trampoline  ; 64 bit doesn't support direct far jmp 

    global exit_interrupt_64
exit_interrupt_64:
    pop rax
    pop rcx
    pop rdx
    pop rbx
    add rsp, 8
    pop rbp
    pop rsi
    pop rdi
    pop r8
    pop r9
    pop r10
    pop r11
    pop r12
    pop r13
    pop r14
    pop r15

    add rsp, 8
    iret

align 64
global int_vector_64
int_vector_64:
%assign i 0
%rep 49
align 8 ; The code below is either 4 or 7 bytes long, so aligning to 8 bytes makes for a equal spaced array of handlers
    push i  ; 2 bytes
%if i == 8 || i == 10 || i == 11 || i == 12 || i == 13 || i == 14 || i == 17 || i == 21 || i == 29 || i == 30
    jmp entry_wrapper_64  ; 2 or 5 bytes
%else
    jmp entry_wrapper_no_error_code_64  ; 2 or 5 bytes
%endif
%assign i (i + 1)
%endrep
