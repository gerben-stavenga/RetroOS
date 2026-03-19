; HELLO.COM — minimal DOS .COM program
; Prints via both INT 10h (BIOS) and INT 21h (DOS), then exits
; Assemble: nasm -f bin -o HELLO.COM hello.asm
org 0x100

    ; Print "BIOS:" via INT 10h AH=0Eh (teletype output)
    mov si, bios_msg
.bios_loop:
    lodsb
    test al, al
    jz .dos_print
    mov ah, 0x0E
    mov bx, 0x0007       ; page 0, light gray
    int 0x10
    jmp .bios_loop

.dos_print:
    ; Print "DOS:" via INT 21h AH=09h
    mov ah, 0x09
    mov dx, dos_msg
    int 0x21

    mov ax, 0x4C00       ; DOS exit, return code 0
    int 0x21

bios_msg db 'BIOS: Hello! ', 0
dos_msg  db 'DOS: Hello!', 0x0D, 0x0A, '$'
