; I installs resident INT 0 + INT 60h checker. A checks the alias,
; C also checks chaining and full registers. R checks vector restoration.
bits 16
org 0x100
    mov si, 0x81
.skip:
    lodsb
    cmp al, ' '
    je .skip
    cmp al, 'I'
    je install
    cmp al, 'R'
    je restored
    mov [mode], al
    mov ax, 0x3500
    int 0x21
    mov ax, es
    test ax, 0x20
    jnz fail
    mov ax, bx
    and ax, 0xfdff
    cmp ax, 0x2000
    jb fail
    cmp ax, 0x200f
    ja fail
    cmp byte [es:bx], 0xea
    jne fail
    cmp byte [mode], 'C'
    jne pass
    mov eax, 0x12345678
    mov ebx, 0x87654321
    mov edx, 0x55aa33cc
    int 0
    cmp eax, 0x12345678
    jne fail
    cmp ebx, 0x87654321
    jne fail
    cmp edx, 0x55aa33cc
    jne fail
    jmp pass
restored:
    mov ax, 0x1234
    int 0x60
    cmp ax, 0x5678
    jne fail
    test bx, bx
    jz fail
pass:
    mov dx, good
    mov ah, 9
    int 0x21
    mov ax, 0x4c00
    int 0x21
fail:
    mov dx, bad
    mov ah, 9
    int 0x21
    mov ax, 0x4c01
    int 0x21
install:
    mov dx, divide_handler
    mov ax, 0x2500
    int 0x21
    mov dx, query_handler
    mov ax, 0x2560
    int 0x21
    mov dx, resident_end + 15
    shr dx, 4
    mov ax, 0x3100
    int 0x21
divide_handler:
    inc word [cs:hits]
    iret
query_handler:
    push es
    xor ax, ax
    mov es, ax
    cmp word [es:0], divide_handler
    jne .bad
    mov ax, cs
    cmp word [es:2], ax
    jne .bad
    mov bx, [cs:hits]
    mov ax, 0x5678
    pop es
    iret
.bad:
    xor ax, ax
    pop es
    iret
hits dw 0
mode db 0
good db 'IVT0 PROBE PASS',13,10,'$'
bad db 'IVT0 PROBE FAIL',13,10,'$'
resident_end:
