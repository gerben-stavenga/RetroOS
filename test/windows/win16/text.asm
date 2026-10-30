bits 16
segment _TEXT public class=CODE use16
extern Debug, Exit, AnsiLowerBuff, AnsiUpperBuff, GlobalAlloc, GlobalLock, GlobalFree
global _start
_start:
    mov [initial_sp],sp
    push ds
    push word buffer
    push word 5
    call far AnsiLowerBuff
    cmp ax,5
    jne fail
    cmp dword [buffer],0xe97a0061
    jne fail
    cmp word [buffer+4],0x5821
    jne fail
    push ds
    push word buffer
    push word 5
    call far AnsiUpperBuff
    cmp ax,5
    jne fail
    cmp dword [buffer],0xc95a0041
    jne fail
    cmp word [buffer+4],0x5821
    jne fail
    ; A Win16 count of zero means exactly 64 KiB, including embedded NULs.
    push word 0x40
    push dword 65536
    call far GlobalAlloc
    test ax,ax
    jz fail
    mov [handle],ax
    push ax
    call far GlobalLock
    mov [buffer_sel],dx
    mov es,dx
    mov byte [es:0],'A'
    mov byte [es:65535],'Z'
    push dx
    push word 0
    push word 0
    call far AnsiLowerBuff
    test ax,ax
    jnz fail
    mov es,[buffer_sel]
    cmp byte [es:0],'a'
    jne fail
    cmp byte [es:65535],'z'
    jne fail
    push word [buffer_sel]
    push word 0
    push word 0
    call far AnsiUpperBuff
    test ax,ax
    jnz fail
    mov es,[buffer_sel]
    cmp byte [es:0],'A'
    jne fail
    cmp byte [es:65535],'Z'
    jne fail
    push ds
    pop es
    push word [handle]
    call far GlobalFree
    test ax,ax
    jnz fail
    cmp sp,[initial_sp]
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
buffer db 'A',0,'Z',0xc9,'!','X'
initial_sp dw 0
handle dw 0
buffer_sel dw 0
passed db 'WIN16 TEXT PASS',0
failed db 'WIN16 TEXT FAIL',0
segment STACK stack class=STACK use16
    resb 8192
group DGROUP _DATA STACK
