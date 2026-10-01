; TSRSESS.COM I installs with AH=31h; L uses the older INT 27h.
; TSRSESS.COM C checks the resident INT 60h hook.
; The check must also work from a nested COMMAND.COM launched by a batch.
bits 16
org 0x100

    cmp byte [0x81], 'C'
    je check

    mov ax, 0x3560
    int 0x21
    mov [old_vector], bx
    mov [old_vector+2], es
    mov dx, handler
    mov ax, 0x2560
    int 0x21
    cmp byte [0x81], 'L'
    jne modern_tsr
    mov dx, resident_end
    int 0x27
modern_tsr:
    mov dx, resident_end + 15
    shr dx, 4
    mov ax, 0x3100
    int 0x21

handler:
    cmp ax, 0x1234
    jne chain
    mov ax, 0x5678
    iret
chain:
    jmp far [cs:old_vector]
old_vector dd 0
resident_end:

check:
    mov ax, 0x1234
    int 0x60
    cmp ax, 0x5678
    jne fail
    mov dx, pass_msg
    mov ah, 0x09
    int 0x21
    mov ax, 0x4c00
    int 0x21
fail:
    mov dx, fail_msg
    mov ah, 0x09
    int 0x21
    mov ax, 0x4c01
    int 0x21

pass_msg db 'TSR SESSION PASS', 13, 10, '$'
fail_msg db 'TSR SESSION FAIL', 13, 10, '$'
