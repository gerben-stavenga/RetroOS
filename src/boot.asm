[org 0x7c00]
[bits 16]
    xor ax, ax
    mov ds, ax
    mov es, ax
    mov ss, ax
    mov sp, 0x7c00
    mov si, msg
    call print
    push edx  ; save drive
    mov al, 4
    mov bx, 0x1000
    call readdisk
    mov si, msg
    call print
    jmp 0x0:0x1000

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

msg:
    db "Hello, World!", 13, 10, 0

    times 510-($-$$) db 0
    dw 0xaa55
