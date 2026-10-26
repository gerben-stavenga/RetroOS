bits 16
segment _TEXT public class=CODE use16
extern CallWindowProc, Debug, Exit
global _start
_start:
    mov [initial_sp], sp
    push cs
    push word callback
    push word 0
    push word 0
    push word 8
    push dword 0
    mov bx, 0x1234
    mov si, 0x5678
    mov di, 0x9abc
    call far CallWindowProc
    cmp ax, 9
    jne fail
    cmp dx, 0
    jne fail
    cmp bx, 0x1234
    jne fail
    cmp si, 0x5678
    jne fail
    cmp di, 0x9abc
    jne fail
    push cs
    push word forward
    push word 0
    push word 0x81
    push word 0
    push ds
    push word payload
    call far CallWindowProc
    cmp ax, 0x3344
    jne fail
    cmp dx, 0x1122
    jne fail
    cmp sp, [initial_sp]
    jne fail
    push ds
    push word passed
    call far Debug
    push word 0
    call far Exit
fail:
    push ds
    push word failed
    call far Debug
    push word 1
    call far Exit
callback:
    push bp
    mov bp, sp
    mov ax, [bp+10]
    test ax, ax
    jz .base
    dec ax
    push cs
    push word callback
    push word 0
    push word 0
    push ax
    push dword 0
    call far CallWindowProc
    inc ax
    jmp .return
.base:
    mov ax, 1
.return:
    xor dx, dx
    pop bp
    retf 10
forward:
    push bp
    mov bp, sp
    les bx, [bp+6]
    mov ax, [es:bx]
    mov dx, [es:bx+2]
    pop bp
    retf 10
segment _DATA public class=DATA use16
payload: dd 0x11223344
initial_sp: dw 0
passed: db 'WIN16 BRIDGE PASS',0
failed: db 'WIN16 BRIDGE FAIL',0
segment STACK stack class=STACK use16
    resb 8192
group DGROUP _DATA STACK
