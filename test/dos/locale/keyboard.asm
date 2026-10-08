bits 16
org 0x100
    mov dx, ready
    mov ah,9
    int 0x21
    mov di, output
.next:
    mov ah,0x10
    int 0x16
    test al,al
    jz .next
    mov bl,al
    shr al,4
    call digit
    mov al,bl
    and al,15
    call digit
    mov al,' '
    stosb
    cmp bl,13
    jne .next
    mov al,'$'
    stosb
    mov dx,result
    mov ah,9
    int 0x21
    mov ax,0x4c00
    int 0x21
digit:
    add al,'0'
    cmp al,'9'
    jbe .store
    add al,7
.store:
    stosb
    ret
ready db 'KEYBOARD READY',13,10,'$'
result db 'KEYBOARD DOS '
output times 256 db 0
