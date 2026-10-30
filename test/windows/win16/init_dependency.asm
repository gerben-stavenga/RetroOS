bits 16
segment _TEXT public class=CODE use16
global _start, Check
_start:
    cmp cx,64
    jne fail
    mov bx,ds
    cmp ax,bx
    jne fail
    cmp di,bx
    jne fail
    inc word [count]
    mov ax,1
    retf
fail:
    xor ax,ax
    retf
Check:
    push ds
    mov ax,seg count
    mov ds,ax
    mov ax,[count]
    pop ds
    retf
segment _DATA public class=DATA use16
count dw 0
group DGROUP _DATA
