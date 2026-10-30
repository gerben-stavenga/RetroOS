bits 16
segment _TEXT public class=CODE use16
global _start, Check
_start:
    xor ax,ax
    retf
Check:
    mov ax,0xbeef
    retf
segment _DATA public class=DATA use16
    dw 0
group DGROUP _DATA
