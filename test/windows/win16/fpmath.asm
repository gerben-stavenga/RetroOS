bits 16
segment _TEXT public class=CODE use16
extern FpMath, Debug, Exit, GetTickCount
global _start
_start:
    call far GetTickCount
    mov si, sp
    xor bx, bx
    call far FpMath
    mov bx, 11
    call far FpMath
    cmp ax, 1
    jne fail
    test dx, dx
    jnz fail
    mov bx, 4
    mov ax, 0x037f
    call far FpMath
    mov bx, 5
    call far FpMath
    cmp ax, 0x037f
    jne fail
    fld1
    fld1
    faddp st1, st0
    mov bx, 7
    xor ax, ax
    call far FpMath
    cmp ax, 2
    jne fail
    test dx, dx
    jnz fail
    fld dword [fraction]
    mov bx, 7
    mov ax, 0x0c00
    call far FpMath
    cmp ax, 1
    jne fail
    test dx, dx
    jnz fail
    mov bx, 5
    call far FpMath
    cmp ax, 0x037f
    jne fail
    fld dword [fraction]
    mov bx, 6
    xor ax, ax
    call far FpMath
    mov bx, 7
    xor ax, ax
    call far FpMath
    cmp ax, 2
    jne fail
    cmp sp, si
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
segment _DATA public class=DATA use16
fraction dd 1.75
passed db 'WIN16 FPMATH PASS',0
failed db 'WIN16 FPMATH FAIL',0
segment STACK stack class=STACK use16
resb 4096
group DGROUP _DATA STACK
