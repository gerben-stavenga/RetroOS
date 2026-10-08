bits 16
org 0x100
    mov ax, 0x3800
    mov dx, buffer
    int 0x21
    jc fail
    cmp word [canary], 0xbeef
    jne fail
    cmp dword [buffer+18], 0
    je fail
    mov ax, bx
    mov di, country
    call hex
    mov ax, [buffer]
    mov di, date
    call hex
    xor ax, ax
    mov al, [buffer+9]
    mov di, decimal
    call hex
    mov al, [buffer+15]
    mov di, currency
    call hex
    mov ax, 0x6601
    int 0x21
    jc fail
    mov ax, bx
    mov di, oem
    call hex
    mov ax, dx
    mov di, system
    call hex
    mov ax, 0x38ff
    mov bx, 1
    mov dx, buffer
    int 0x21
    jc fail
    cmp bx, 1
    jne fail
    cmp word [buffer], 0
    jne fail
    mov ax, 0x38ff
    mov bx, 999
    mov dx, buffer
    int 0x21
    jnc fail
    mov dx, message
    mov ah, 9
    int 0x21
    mov ax, 0x4c00
    int 0x21
hex:
    push ax
    push bx
    push cx
    mov cx, 4
.digit:
    rol ax, 1
    rol ax, 1
    rol ax, 1
    rol ax, 1
    mov bl, al
    and bl, 15
    add bl, '0'
    cmp bl, '9'
    jbe .write
    add bl, 7
.write:
    mov [di], bl
    inc di
    loop .digit
    pop cx
    pop bx
    pop ax
    ret
fail:
    mov dx, failed
    mov ah, 9
    int 0x21
    mov ax, 0x4c01
    int 0x21
message db 'LOCALE DOS PASS country='
country db '0000 oem='
oem db '0000 system='
system db '0000 date='
date db '0000 decimal='
decimal db '0000 currency='
currency db '0000',13,10,'$'
failed db 'LOCALE DOS FAIL',13,10,'$'
buffer times 32 db 0
canary dw 0xbeef
