bits 16
segment _TEXT public class=CODE use16
extern Dependency, LoadLibrary, GetProcAddress
global _start, Check
_start:
    call far Dependency
    cmp ax,1
    jne fail
    push ds
    push word nested
    call far LoadLibrary
    cmp ax,32
    jb fail
    push ax
    push word 0
    push word 1
    call far GetProcAddress
    mov [entry],ax
    mov [entry+2],dx
    call far [entry]
    cmp ax,1
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
; Eighteen code segments plus DGROUP exceed the old sixteen-segment slot.
%assign n 1
%rep 17
segment PAD%+n public class=CODE use16
    db 0xcb
%assign n n+1
%endrep
segment _DATA public class=DATA use16
count dw 0
entry dd 0
nested db 'INITNEST.DLL',0
group DGROUP _DATA
