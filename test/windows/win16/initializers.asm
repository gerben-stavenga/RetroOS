bits 16
segment _TEXT public class=CODE use16
extern Debug, Exit, GetTickCount, LoadLibrary, GetProcAddress, Dependency
global _start
_start:
    call far GetTickCount
    mov [saved_sp],sp
    mov [saved_ds],ds
    ; A statically imported library must already have run its LibMain.
    call far Dependency
    cmp ax,1
    jne fail
    mov word [iterations],2
.loop:
    push ds
    push word library
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
    dec word [iterations]
    jnz .loop
    mov word [iterations],2
.failure:
    push ds
    push word failure
    call far LoadLibrary
    cmp ax,11
    jne fail
    dec word [iterations]
    jnz .failure
    cmp sp,[saved_sp]
    jne fail
    mov ax,ds
    cmp ax,[saved_ds]
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
saved_sp dw 0
saved_ds dw 0
iterations dw 0
entry dd 0
library db 'INITLARGE.DLL',0
failure db 'INITFAIL.DLL',0
passed db 'WIN16 INITIALIZERS PASS',0
failed db 'WIN16 INITIALIZERS FAIL',0
segment STACK stack class=STACK use16
resb 8192
group DGROUP _DATA STACK
