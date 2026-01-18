; RetroOS Kernel Entry Assembly
; Stack switching and interrupt entry points

%ifidn __OUTPUT_FORMAT__,elf
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
%ifidn __OUTPUT_FORMAT__,elf32
section .note.GNU-stack noalloc noexec nowrite progbits
%endif

section .text
[bits 32]

; Switch to a new stack and call a function
; extern "C" fn switch_stack(new_stack: *mut u8, func: extern "C" fn()) -> !
global SwitchStack
SwitchStack:
    mov eax, [esp + 8]  ; func arg
    mov esp, [esp + 4]  ; new stack arg
    xor ebp, ebp        ; ensure stack frame ends
    call eax            ; should not return
    ud2                 ; trap if it does

; Exit kernel mode and return to interrupted context
; extern "C" fn exit_kernel(regs: *const Regs) -> !
global exit_kernel
exit_kernel:
    cli                     ; disable interrupts while manipulating stack
    mov esp, [esp + 4]      ; load regs pointer as stack
    jmp exit_interrupt      ; restore all registers and iret

; Common interrupt entry - saves all registers
entry_wrapper_no_error_code:
    push dword [esp]        ; duplicate interrupt number as fake error code
entry_wrapper:
    ; Stack at this point: int_num, error_code, eip, cs, eflags [, esp, ss if ring change]

    ; Save all general purpose registers
    pusha                   ; pushes eax, ecx, edx, ebx, esp, ebp, esi, edi

    ; Save segment registers
    push ds
    push es
    push fs
    push gs

    ; Set all segments to kernel data selector
    mov eax, 0x10           ; kernel data selector
    mov ds, eax
    mov es, eax
    mov fs, eax
    mov gs, eax

    ; Save stack pointer (points to saved registers)
    mov eax, esp

    ; Setup a mock stack frame for debugging
    push dword [eax + 56]   ; push return eip
    push dword [eax + 24]   ; push old ebp
    mov ebp, esp

    cld                     ; clear direction flag
    push eax                ; push pointer to saved registers (Regs struct)

    extern isr_handler
    call isr_handler        ; call Rust interrupt handler

    add esp, 12             ; clean up mock frame and argument

exit_interrupt:
    ; Restore segment registers
    pop gs
    pop fs
    pop es
    pop ds

    ; Restore general purpose registers
    popa

    ; Skip error code and interrupt number
    add esp, 8

    ; Return from interrupt
    iret

; Interrupt vector table
; Each entry is 8 bytes (aligned), pushes interrupt number and jumps to entry_wrapper
align 64
global int_vector
int_vector:
%assign i 0
%rep 49
    align 8
    push i
    ; Exceptions that push an error code: 8, 10, 11, 12, 13, 14, 17, 21, 29, 30
%if i == 8 || i == 10 || i == 11 || i == 12 || i == 13 || i == 14 || i == 17 || i == 21 || i == 29 || i == 30
    jmp entry_wrapper
%else
    jmp entry_wrapper_no_error_code
%endif
%assign i (i + 1)
%endrep
