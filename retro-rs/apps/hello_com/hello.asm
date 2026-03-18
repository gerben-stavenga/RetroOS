; HELLO.COM — minimal DOS .COM program
; Prints "Hello from DOS!" via INT 21h and exits
; Assemble: nasm -f bin -o HELLO.COM hello.asm
org 0x100

    mov ah, 0x09        ; DOS print string
    mov dx, msg          ; DS:DX = address of $-terminated string
    int 0x21

    mov ax, 0x4C00       ; DOS exit, return code 0
    int 0x21

msg db 'Hello from DOS!', 0x0D, 0x0A, '$'
