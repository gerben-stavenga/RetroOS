%ifidn __OUTPUT_FORMAT__,elf
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
%ifidn __OUTPUT_FORMAT__,elf32
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
%ifidn __OUTPUT_FORMAT__,elf64
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
section .boot
REALSEG EQU 0x0
CS32 EQU 0x8
CS16 EQU 0x18
DS32 EQU 0x10

[bits 16]
global _start
_start:
    jmp REALSEG:next  ; make sure cs = 0
    global start_msg
align 4
gdt:
    dw 0, 0, 0, 0
    dw 0xFFFF, 0, 0x9A00, 0xCF
    dw 0xFFFF, 0, 0x9200, 0xCF
    dw 0xFFFF, 0, 0x9A00, 0    ; 16 bit code segment
gdt_ptr:
    dw gdt_ptr - gdt - 1
    dd gdt
struc REGS
    .ax resd 1
    .bx resd 1
    .cx resd 1
    .dx resd 1
    .si resd 1
    .di resd 1
    .bp resd 1
    .ds resw 1
    .es resw 1
endstruc
global regs
regs:
    istruc REGS
    iend

next:
    xor esp, esp    ; make sure high bits are zero
    mov ss, sp
    mov sp, 0x1000  ; between 0x500 and 0x1000 is conventional mem

    ; move to pm
    call REALSEG:toggle_pm
    extern BootLoader
    jmp CS32:BootLoader

toggle_pm:
    push ebp
    cli
    lgdt cs:[gdt_ptr] ; load the GDT
    mov ebp, cr0 ; get cr0
    xor ebp, 1 ; toggle PE bit
    mov cr0, ebp ; write cr0
    mov ebp, esp
    xor word [ebp + 6], CS16
    mov bp, ss
    xor bp, DS32
    mov ds, bp
    mov es, bp
    mov ss, bp
    mov fs, bp
    mov gs, bp
    pop ebp
    retf

x86_16_gen_interrupt:
    call CS16:toggle_pm

    push WORD [regs + REGS.es]
    pop es
    push WORD [regs + REGS.ds]
    pop ds

    pushf   ; save flags before call to interrupt handler to mimic int
    call far [ss:esp + 6]  ; call the interrupt
    pushf  ; save flags after interrupt

    call REALSEG:toggle_pm  ; restore data segments

    pop WORD [regs + REGS.ax]  ; flags will end up in eax on return

    jmp CS32:swapregs

[bits 32]
global generate_real_interrupt
generate_real_interrupt:
    mov eax, [esp + 4]  ; get interrupt number
    mov eax, [eax * 4]  ; get interrupt address
    mov [esp + 4], eax  ; replace interrupt number with address
    call swapregs  ; save registers and load interrupt parameters
    jmp CS16:x86_16_gen_interrupt
    ; store interrupt return values and restore registers
swapregs:
    xchg eax, [regs + REGS.ax]
    xchg ebx, [regs + REGS.bx]
    xchg ecx, [regs + REGS.cx]
    xchg edx, [regs + REGS.dx]
    xchg esi, [regs + REGS.si]
    xchg edi, [regs + REGS.di]
    xchg ebp, [regs + REGS.bp]
    ret
