; HELLO.COM — bare-minimum DOS .COM probe: just exit.
; Assemble: nasm -f bin -o HELLO.COM hello.asm
org 0x100

    mov ax, 0x4C00       ; DOS exit, return code 0
    int 0x21
