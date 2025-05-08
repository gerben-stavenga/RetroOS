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
    ; stack int handler return address , error code , interrupt number
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

    mov eax, esp

    ; setup a mock stack frame 
    push dword [eax + 56]  ; push return eip
    push dword [eax + 24]  ; push old ebp 
    mov ebp, esp

    cld
    push eax  ; save esp value as it is before the instruction pointer is pushed
    extern isr_handler
    call isr_handler  ; does not return
    add esp, 12

exit_interrupt:
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
align 8 ; The code below is either 4 or 7 bytes long, so aligning to 8 bytes makes for a equal spaced array of handlers
    push i  ; 2 bytes
%if i == 8 || i == 10 || i == 11 || i == 12 || i == 13 || i == 14 || i == 17 || i == 21 || i == 29 || i == 30
    jmp entry_wrapper  ; 2 or 5 bytes
%else
    jmp entry_wrapper_no_error_code  ; 2 or 5 bytes
%endif
%assign i (i + 1)
%endrep
