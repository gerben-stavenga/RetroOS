[org 0x7c00]
[bits 16]
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x1000

    push edx ; save drive

    mov si, booting_msg
    call print

    mov al, 35
    mov bx, 0x1000
    call readdisk

    ; mov cx, 20
    ; mov si, 0x1000
    ; call printhex

    mov si, loaded_msg
    call print

    ; get cursor
    mov ah, 3
    mov bh, 0
    int 10h
    push edx

    ; move to pm
    cli
    lgdt [gdt_ptr]
    mov bx, 0x10
    mov eax, cr0
    or eax, 1
    mov cr0, eax
    mov ds, bx
    mov es, bx
    mov fs, bx
    mov gs, bx
    jmp 0x8:0x1000

; dl = drive, es:bx = buffer, al = sectors
readdisk:
    mov ah, 0x02
    mov ch, 0x00
    mov cl, 0x02
    mov dh, 0x00
    int 0x13
    jc readdisk
    ret

print:
    lodsb
    or al, al
    jz done
    mov ah, 0x0e
    mov bx, 0x0007
    int 0x10
    jmp print
done:
    ret

printhex:
    push cx
    lodsb
    mov bx, ax
    and bx, 0xFF
    shr bx, 4
    mov cl, [hex + bx]
    mov [hexval], cl
    mov bx, ax
    and bx, 15
    mov cl, [hex + bx]
    mov [hexval + 1], cl
    push si
    mov si, hexval
    call print
    pop si
    pop cx
    dec cx
    jnz printhex
    ret

gdt:
    dw 0, 0, 0, 0
    dw 0xFFFF, 0, 0x9A00, 0xCF
    dw 0xFFFF, 0, 0x9200, 0xCF
gdt_ptr:
    dw gdt_ptr - gdt - 1
    dd gdt

.align
booting_msg:
    db "Booting ...", 13, 10, 0
loaded_msg:
    db "Kernel loaded!", 13, 10, 0
hex:
    db '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
hexval:
    db 0, 0, ' ', 0

    times 510-($-$$) db 0
    dw 0xaa55
