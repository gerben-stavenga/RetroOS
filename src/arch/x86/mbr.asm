REALSEG EQU 0x0
CS32 EQU 0x8
CS16 EQU 0x18
DS32 EQU 0x10

[bits 16]
global _start
_start:
    jmp REALSEG:next  ; make sure cs = 0
next:
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x1000  ; between 0x500 and 0x1000 is conventional mem

    push edx ; save drive

    mov si, booting_msg
    call print

    ;  // clear BSS
    extern _edata
    extern _end
    mov di, _edata
    mov cx, _end
    sub cx, di
    xor ax, ax
    cld
    rep stosb

    ;  // load rest of bootloader
    mov ax, _edata + 511
    mov bx, _start + 512
    sub ax, bx
    shr ax, 9  ; (_edata - _start - 1) / 512 number of sectors that must be loaded
    call readdisk

    mov si, loaded_msg
    call print

    ; move to pm
    call switch_to_pm
    jmp CS32:start32

; dx = drive, es:bx = buffer, ax = num sectors
readdisk:
    mov ah, 0x02
    mov ch, 0x00
    mov cl, 0x02
    mov dh, 0x00
    int 0x13
    jc readdisk
    ret

print_char:
    mov ah, 0x0e
    mov bx, 0x0007
    int 0x10
print:
    lodsb
    or al, al
    jnz print_char
    ret

switch_to_pm:
    push eax
    cli
    lgdt cs:[gdt_ptr] ; load the GDT
    mov eax, cr0 ; get cr0
    or eax, 1 ; set PE bit
    mov cr0, eax ; write cr0
    mov ax, DS32 ; set data segment to 0x10
    jmp CS16:update_segs
update_segs:
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov fs, ax
    mov gs, ax
    pop eax
    ret

switch_to_rm:  ; execute in 16 bit protected mode
    push eax
    cli
    mov eax, cr0 ; get cr0
    and eax, 0xFFFFFFFE ; clear PE bit
    mov cr0, eax ; write cr0
    mov ax, REALSEG
    jmp REALSEG:update_segs

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
    extern regs
x86_16_gen_interrupt:
    call switch_to_rm

    push WORD [regs + REGS.es]
    pop es
    push WORD [regs + REGS.ds]
    pop ds

    pushf   ; save flags before call to interrupt handler to mimic int
    call far [esp + 6]  ; call the interrupt

    push ds
    ; restore ds to 0, so we can use it to access the real mode data
    push REALSEG
    pop ds
    pop WORD [regs + REGS.ds]
    push es
    pop WORD [regs + REGS.es]
    pushf  ; save flags after interrupt
    pop WORD [regs + REGS.flags]

    call switch_to_pm
    jmp CS32:swapregs

[bits 32]
start32:
    ; drive already pushed
    extern BootLoader
    call BootLoader
    add esp, 4  ; remove drive from stack
    mov edi, eax
    jmp DWORD [edi]  ; boot_data.kernel

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


align 4
gdt:
    dw 0, 0, 0, 0
    dw 0xFFFF, 0, 0x9A00, 0xCF
    dw 0xFFFF, 0, 0x9200, 0xCF
    dw 0xFFFF, 0, 0x9A00, 0    ; 16 bit code segment
gdt_ptr:
    dw gdt_ptr - gdt - 1
    dd gdt

booting_msg:
    db "Start boot ...", 13, 10, 0
loaded_msg:
    db "Bootloader loaded!", 13, 10, 0

    times 510-($-$$) db 0
    dw 0xaa55
