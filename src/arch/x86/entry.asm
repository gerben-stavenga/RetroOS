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
global _start
_start:
    mov ebx, ecx
    push ecx ; boot data pointer
    extern PrepareKernel
    call PrepareKernel
    mov esp, eax  ; PrepareKernel returns the new kernel stack in eax
    extern KernelInit
    lea eax, [KernelInit]
    push ebx
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

    cld
    push esp  ; save esp value as it is before the instruction pointer is pushed
    call isr_handler
    mov esp, eax  ; either a pop or a change of stack to a new process

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
align 8 ; The code below is either 5 or 7 bytes long, so aligning to 8 bytes makes for a equal spaced array of handlers
%if i == 8 || i == 10 || i == 11 || i == 12 || i == 13 || i == 14 || i == 17 || i == 21 || i == 29 || i == 30
    ; error code is already pushed by CPU
%else
    ; push zero error code to make the stack layout uniform
    push 0
%endif
    call entry_wrapper  ; the interrupt number can be deduced from the return address pushed by the call instruction
%assign i (i + 1)
%endrep
