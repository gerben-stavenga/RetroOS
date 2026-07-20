; HELLO.COM -- minimal DOS .COM that prints a greeting and exits.
; Doubles as a probe for the COM loader and INT 21h AH=09h string output.
; Assemble: nasm -f bin -o HELLO.COM hello.asm
org 0x100

    mov ah, 0x09          ; DOS write-string
    mov dx, msg
    int 0x21
    mov ax, 0x4C00        ; DOS exit, return code 0
    int 0x21

msg db "Hello from HELLO.COM!", 13, 10, '$'
