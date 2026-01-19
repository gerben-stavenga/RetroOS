; RetroOS Rust Bootloader - MBR Entry
; This is the minimal 16-bit real mode code that cannot be written in Rust.
; It sets up protected mode and jumps to the Rust bootloader.

%ifidn __OUTPUT_FORMAT__,elf
section .note.GNU-stack noalloc noexec nowrite progbits
%endif
%ifidn __OUTPUT_FORMAT__,elf32
section .note.GNU-stack noalloc noexec nowrite progbits
%endif

section .boot
REALSEG EQU 0x0
CS32 EQU 0x8
CS16 EQU 0x18
DS32 EQU 0x10

; BIOS register structure for interrupt calls
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

[bits 16]
extern regs
global _start
_start:
    jmp REALSEG:next  ; normalize cs = 0

align 4
gdt:
    ; Null descriptor
    dw 0, 0, 0, 0
    ; CS32 (0x08): 32-bit code segment, base=0, limit=4GB
    dw 0xFFFF, 0, 0x9A00, 0xCF
    ; DS32 (0x10): 32-bit data segment, base=0, limit=4GB
    dw 0xFFFF, 0, 0x9200, 0xCF
    ; CS16 (0x18): 16-bit code segment for BIOS callbacks
    dw 0xFFFF, 0, 0x9A00, 0
gdt_ptr:
    dw gdt_ptr - gdt - 1
    dd gdt

next:
    xor esp, esp    ; clear high bits of esp
    mov ss, sp
    mov sp, regs    ; stack grows down from regs struct

    ; Switch to protected mode
    call REALSEG:toggle_pm

    ; Calculate bootloader size for loading remaining sectors
    extern _edata
    mov ecx, _edata - _start - 512  ; number of bytes to load (passed to boot_main)

    ; Jump to Rust bootloader entry
    extern boot_main
    jmp CS32:boot_main

; toggle_pm: Toggle between real mode and protected mode
; Uses the return address on the stack to switch code segment
toggle_pm:
    push ebp
    cli
    lgdt cs:[gdt_ptr]   ; load GDT (cs override needed in real mode)
    mov ebp, cr0
    xor ebp, 1          ; toggle PE bit
    mov cr0, ebp
    mov ebp, esp
    xor word [ebp + 6], CS16  ; modify return segment on stack
    mov bp, ss
    xor bp, DS32
    mov ds, bp
    mov es, bp
    mov ss, bp
    mov fs, bp
    mov gs, bp
    pop ebp
    retf

; x86_16_gen_interrupt: Execute BIOS interrupt from protected mode
; Called from generate_real_interrupt after switching to 16-bit code segment
x86_16_gen_interrupt:
    call CS16:toggle_pm     ; switch to real mode

    ; Load segment registers from regs struct
    push WORD [regs + REGS.es]
    pop es
    push WORD [regs + REGS.ds]
    pop ds

    pushf                   ; push flags (mimics INT instruction)
    call far [ss:esp + 6]   ; call BIOS interrupt handler
    pushf                   ; save flags after interrupt

    call REALSEG:toggle_pm  ; switch back to protected mode

    pop WORD [regs + REGS.ax]  ; store flags in regs.ax (returned to caller)

    jmp CS32:swapregs

[bits 32]
global generate_real_interrupt
generate_real_interrupt:
    mov eax, [esp + 4]      ; get interrupt number
    mov eax, [eax * 4]      ; fetch interrupt vector from IVT
    mov [esp + 4], eax      ; replace parameter with handler address
    call swapregs           ; save current regs, load BIOS params
    jmp CS16:x86_16_gen_interrupt

; swapregs: Swap CPU registers with regs struct
; Used to pass parameters to BIOS and retrieve results
swapregs:
    xchg eax, [regs + REGS.ax]
    xchg ebx, [regs + REGS.bx]
    xchg ecx, [regs + REGS.cx]
    xchg edx, [regs + REGS.dx]
    xchg esi, [regs + REGS.si]
    xchg edi, [regs + REGS.di]
    xchg ebp, [regs + REGS.bp]
    ret
