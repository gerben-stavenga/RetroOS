; RetroOS Kernel Entry Assembly
; Stack switching and interrupt entry points
; Supports both 32-bit and 64-bit userspace with unified Regs struct

%ifidn __OUTPUT_FORMAT__,elf
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
%ifidn __OUTPUT_FORMAT__,elf32
section .note.GNU-stack noalloc noexec nowrite progbits
%endif

; =============================================================================
; 32-bit code section
; =============================================================================
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

; Exit kernel mode and return to interrupted context (32-bit)
; extern "C" fn exit_kernel(regs: *const Regs) -> !
global exit_kernel
exit_kernel:
    cli                     ; disable interrupts while manipulating stack
    mov esp, [esp + 4]      ; load regs pointer as stack
    jmp exit_interrupt_32   ; restore all registers and iret

; Macro to push a 32-bit register as 64-bit (with high dword = 0)
%macro push64_32 1
    push dword 0            ; high 32 bits
    push %1                 ; low 32 bits
%endmacro

; Common 32-bit interrupt entry - saves all registers as 64-bit values
; Stack on entry: [err_code], eip, cs, eflags [, esp, ss]
; int_num was pushed by vector table
entry_wrapper_32_no_error_code:
    ; No error code - duplicate int_num as placeholder (matches original C++ approach)
    push dword [esp]
entry_wrapper_32:
    ; Stack: int_num(32), err_code(32), eip, cs, eflags [, esp, ss]
    ; Need: int_num(64), err_code(64), Frame32._pad(20), eip, ...
    sub esp, 12             ; partial space for padding
    ; Push 64-bit err_code (high=0, low=value)
    push dword 0
    push dword [esp+20]     ; err_code was at ESP+4, now at ESP+20
    ; Push 64-bit int_num (high=0, low=value)
    push dword 0
    push dword [esp+24]     ; int_num was at ESP+0, now at ESP+24
    ; Layout: int_num(64), err_code(64), 12-byte gap, old_int/err(8), eip
    ; Padding between err_code and eip = 12 + 8 = 20 bytes

    ; Save general purpose registers (zero-extended to 64-bit)
    push64_32 eax
    push64_32 ecx
    push64_32 edx
    push64_32 ebx
    push64_32 esp           ; dummy esp
    push64_32 ebp
    push64_32 esi
    push64_32 edi

    ; Push r8-r15 as zeros (not available in 32-bit mode)
    times 8 push dword 0    ; r8 low
    times 8 push dword 0    ; r8 high ... r15 high (8 registers * 8 bytes = 64 bytes total, but need 16 pushes)

    ; Save segment registers (zero-extended to 64-bit)
    xor eax, eax
    mov ax, ds
    push64_32 eax
    mov ax, es
    push64_32 eax
    mov ax, fs
    push64_32 eax
    mov ax, gs
    push64_32 eax

    ; Set all segments to kernel data selector
    mov eax, 0x10           ; kernel data selector
    mov ds, eax
    mov es, eax
    mov fs, eax
    mov gs, eax

    ; Call common handler (ESP points to Regs struct)
    call call_isr_handler

exit_interrupt_32:
    ; Restore segment registers
    pop eax                 ; gs high (discard)
    pop eax                 ; gs low
    mov gs, ax
    pop eax                 ; fs high (discard)
    pop eax                 ; fs low
    mov fs, ax
    pop eax                 ; es high (discard)
    pop eax                 ; es low
    mov es, ax
    pop eax                 ; ds high (discard)
    pop eax                 ; ds low
    mov ds, ax

    ; Skip r15-r8 (64 bytes = 8 registers * 8 bytes)
    add esp, 64

    ; Restore general purpose registers (skip high dwords)
    pop edi
    add esp, 4              ; skip high dword
    pop esi
    add esp, 4
    pop ebp
    add esp, 4
    add esp, 8              ; skip rsp_dummy
    pop ebx
    add esp, 4
    pop edx
    add esp, 4
    pop ecx
    add esp, 4
    pop eax
    add esp, 4

    ; Skip int_num and err_code (16 bytes total, both 64-bit)
    add esp, 16

    ; Remove frame padding (20 bytes)
    add esp, 20

    ; Return from interrupt (CPU pops eip, cs, eflags [, esp, ss])
    iret

; =============================================================================
; Common ISR handler call (32-bit)
; Called from both 32-bit and 64-bit entry points
; Input: ESP points to Regs struct
; =============================================================================
call_isr_handler:
    mov eax, esp
    add eax, 4              ; adjust for return address on stack

    ; Setup a mock stack frame for debugging
    ; Regs layout: gs/fs/es/ds (32) + r15-r8 (64) + rdi/rsi/rbp/... (64) + int/err (16) + frame (40)
    ; Offset to frame.eip: 32 + 64 + 64 + 16 + 20 (Frame32._pad) = 196
    ; Offset to rbp: 32 + 64 + 16 (rdi+rsi) = 112
    push dword [eax + 196]  ; push return eip
    push dword [eax + 112]  ; push old ebp (low 32 bits of rbp)
    mov ebp, esp

    cld                     ; clear direction flag
    push eax                ; push pointer to saved registers (Regs struct)

    extern isr_handler
    call isr_handler        ; call Rust interrupt handler

    add esp, 12             ; clean up mock frame and argument
    ret

; =============================================================================
; Trampoline for 64-bit to 32-bit transition
; Called via far jump from 64-bit entry, jumps back via far jump
; =============================================================================
trampoline_64_to_32:
    ; Now in 32-bit mode, ESP = low 32 bits of RSP (points to Regs)
    call call_isr_handler
    ; Far jump back to 64-bit mode (indirect via memory)
    jmp far [far_ptr_64]


; =============================================================================
; 64-bit code section (for future use when kernel runs in long mode)
; =============================================================================
[bits 64]

; Common 64-bit interrupt entry - saves all registers
entry_wrapper_64_no_error_code:
    ; No error code - duplicate int_num as placeholder (matches 32-bit approach)
    push qword [rsp]
entry_wrapper_64:
    ; Stack: int_num, err_code, rip, cs, rflags, rsp, ss (all 64-bit)
    ; Frame64 is 40 bytes, no padding needed (unlike Frame32 which has 20-byte _pad)

    ; Save general purpose registers
    push rax
    push rcx
    push rdx
    push rbx
    push rsp                ; dummy rsp
    push rbp
    push rsi
    push rdi

    ; Save r8-r15
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    ; Save segment registers (zero-extended)
    xor rax, rax
    mov ax, ds
    push rax
    mov ax, es
    push rax
    mov ax, fs
    push rax
    mov ax, gs
    push rax

    ; Set segments to kernel data selector
    mov ax, 0x10
    mov ds, ax
    mov es, ax

    ; Far jump to 32-bit trampoline (indirect via memory)
    jmp far [rel far_ptr_32]

exit_interrupt_64:
    ; Restore segment registers
    pop rax
    mov gs, ax
    pop rax
    mov fs, ax
    pop rax
    mov es, ax
    pop rax
    mov ds, ax

    ; Restore r15-r8
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8

    ; Restore general purpose registers
    pop rdi
    pop rsi
    pop rbp
    add rsp, 8              ; skip rsp_dummy
    pop rbx
    pop rdx
    pop rcx
    pop rax

    ; Skip int_num and err_code (16 bytes in 64-bit mode)
    add rsp, 16

    iretq

; =============================================================================
; Interrupt vector table (32-bit)
; =============================================================================
[bits 32]

; =============================================================================
; Mode toggle entry point - calls trampoline at 0xF000
; fastcall: ECX = new CR3
; =============================================================================
global toggle_prot_compat
toggle_prot_compat:
    jmp 0xF000

; =============================================================================
; Far jump pointers for mode switching
; =============================================================================
align 8
far_ptr_32:
    dq trampoline_64_to_32  ; 64-bit offset (used from 64-bit mode, m16:64)
    dw 0x08                 ; 32-bit code segment

align 8
far_ptr_64:
    dd exit_interrupt_64    ; 32-bit offset (in 32-bit mode, only low 32 bits used)
    dw 0x18                 ; 64-bit code segment

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
    jmp entry_wrapper_32
%else
    jmp entry_wrapper_32_no_error_code
%endif
%assign i (i + 1)
%endrep

; =============================================================================
; 64-bit interrupt vector table (for future use)
; =============================================================================
[bits 64]

align 64
global int_vector_64
int_vector_64:
%assign i 0
%rep 49
    align 8
    push i
%if i == 8 || i == 10 || i == 11 || i == 12 || i == 13 || i == 14 || i == 17 || i == 21 || i == 29 || i == 30
    jmp entry_wrapper_64
%else
    jmp entry_wrapper_64_no_error_code
%endif
%assign i (i + 1)
%endrep

; =============================================================================
; Mode switching trampoline - copied to 0xF000 (identity-mapped)
; fastcall: ECX = new CR3
; Toggles between protected mode and long mode (compat) by XORing EFER.LME
; =============================================================================
section .trampoline progbits alloc exec nowrite
global trampoline_start
global trampoline_end
[bits 32]
trampoline_start:
    ; Save callee-saved register and store new CR3
    push ebp
    mov ebp, ecx        ; ECX = new CR3 from fastcall

    ; Disable paging
    mov eax, cr0
    and eax, ~(1 << 31)     ; Clear PG bit
    mov cr0, eax

    ; Toggle long mode in EFER MSR (clobbers EAX, EDX, ECX)
    mov ecx, 0xC0000080     ; EFER MSR
    rdmsr
    xor eax, (1 << 8)       ; Toggle LME bit
    wrmsr

    ; Load new page tables (also flushes TLB)
    mov cr3, ebp

    ; Enable paging
    mov eax, cr0
    or eax, (1 << 31)       ; Set PG bit
    mov cr0, eax

    ; Restore callee-saved register and return
    pop ebp
    ret

trampoline_toggle_end:

align 16
trampoline_end:
