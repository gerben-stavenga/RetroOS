section .text
    extern kmain ; coded in c
    extern gdt_ptr
    extern idt_ptr
    extern real_mode_idt_ptr
global _start
_start:
[bits 32]
    ; stack contains drive number
    call kmain
    jmp $

[bits 16]
switch_to_pm:
    cli
    lgdt [gdt_ptr] ; load the GDT
    lidt [idt_ptr] ; load the IDT
    mov dx, 0x10 ; set data segment to 0x10
    mov eax, cr0 ; get cr0
    or eax, 1 ; set PE bit
    mov cr0, eax ; write cr0
    jmp 0x28:update_segs ; 0x28 is 16 bit protected code segment
update_segs:
    mov ds, dx
    mov es, dx
    mov ss, dx
    mov fs, dx
    mov gs, dx
    ret

switch_to_rm:  ; execute in 16 bit protected mode
    cli
    lidt [real_mode_idt_ptr] ; load the IDT
    xor dx, dx ; set data segment to 0x0
    mov eax, cr0 ; get cr0
    and eax, 0xFFFFFFFE ; clear PE bit
    mov cr0, eax ; write cr0
    jmp 0x0:update_segs

handler:
    dd 0x0
extern regs
global x86_16_gen_interrupt
x86_16_gen_interrupt:
    mov [handler], eax

    call switch_to_rm

    call swapregs

    mov ax, [regs + REGS.es]
    mov es, ax
    mov ax, [regs + REGS.ds]
    mov ds, ax
    mov ax, [regs + REGS.ax]

    ; mimic int
    pushf
    call [handler]

    mov [cs:regs + REGS.ax], ax
    mov ax, ds
    mov [cs:regs + REGS.ds], ax
    mov ax, es
    mov [cs:regs + REGS.es], ax

    pushf  ; save flags after interrupt
    pop WORD [regs + REGS.flags]

    call swapregs

    call switch_to_pm

    db 0x66  ; called from 32 bit code, so we need to pop 32 bit return address
    retf

swapregs:
    xchg ebx, [regs + REGS.bx]
    xchg ecx, [regs + REGS.cx]
    xchg edx, [regs + REGS.dx]
    xchg esi, [regs + REGS.si]
    xchg edi, [regs + REGS.di]
    xchg ebp, [regs + REGS.bp]
    ret

[bits 32]

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

struc REGS
    .ax resd 1
    .bx resd 1
    .cx resd 1
    .dx resd 1
    .si resd 1
    .di resd 1
    .bp resd 1
    .flags resd 1
    .ds resw 1
    .es resw 1
endstruc