[org 0x7c00]
BOOT_LOADER_ADDR EQU 0x7e00
BOOT_LOADER_SECTORS EQU 5
REALSEG EQU 0x0
CS32 EQU 0x8
CS16 EQU 0x18
DS32 EQU 0x10

[bits 16]
    jmp REALSEG:start  ; make sure cs = 0
    times 8-($-$$) db 0
regs:
    times 9 dd 0    ; 0x8 int regs
    dd x86_16_gen_interrupt ; 0x2C offset:seg of real mode interrupt
    dw CS16 ;
align 4
start:
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x1000  ; between 0x500 and 0x1000 is conventional mem

    push edx ; save drive

    mov si, booting_msg
    call print

    mov ax, BOOT_LOADER_SECTORS
    mov bx, BOOT_LOADER_ADDR
    call readdisk

    mov si, loaded_msg
    call print

    ; move to pm
    call switch_to_pm
    pop edx ; restore drive
    jmp CS32:BOOT_LOADER_ADDR

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

switch_to_pm:
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
    ret

switch_to_rm:  ; execute in 16 bit protected mode
    cli
    mov eax, cr0 ; get cr0
    and eax, 0xFFFFFFFE ; clear PE bit
    mov cr0, eax ; write cr0
    mov ax, REALSEG
    jmp REALSEG:update_segs

handler:
    dd 0x0
x86_16_gen_interrupt:
    mov eax, [eax * 4]
    mov [handler], eax

    call switch_to_rm

    call swapregs

    push WORD [regs + REGS.es]
    pop es
    push WORD [regs + REGS.ds]
    pop ds

    ; mimic int
    pushf
    call far [cs:handler]

    push ds
    push 0
    pop ds
    pop WORD [regs + REGS.ds]
    pushf  ; save flags after interrupt
    pop WORD [regs + REGS.flags]
    push es
    pop WORD [regs + REGS.es]

    call swapregs

    call switch_to_pm

    db 0x66  ; called from 32 bit code, so we need to pop 32 bit return address
    retf

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
