bits 16
segment _TEXT public class=CODE use16
extern mmioOpen, mmioGetInfo, mmioClose, GetSelectorLimit
global _start
_start:
    mov word [iterations],40
.again:
    push ds
    pop es
    xor ax,ax
    mov di,info
    mov cx,33
    rep stosw
    mov dword [info+4],'MEM '
    mov dword [info+16],65536
    push dword 0
    push ds
    push word info
    push dword 0x10002
    call far mmioOpen
    test ax,ax
    jz fail
    mov [handle],ax
    push ax
    push ds
    push word info
    push word 0
    call far mmioGetInfo
    test ax,ax
    jnz fail
    cmp dword [info+16],65536
    jne fail
    mov ax,[info+22]
    test ax,ax
    jz fail
    push ax
    call far GetSelectorLimit
    ; The entire buffer, including its initial offset, must fit the alias.
    movzx ecx,word [info+20]
    add ecx,65535
    shl edx,16
    mov dx,ax
    cmp edx,ecx
    jb fail
    les di,[info+20]
    mov ax,0x5aa5
    mov cx,32768
    rep stosw
    les bx,[info+20]
    cmp word [es:bx],0x5aa5
    jne fail
    add bx,65534
    cmp word [es:bx],0x5aa5
    jne fail
    push ds
    pop es
    push word [handle]
    push word 0
    call far mmioClose
    test ax,ax
    jnz fail
    dec word [iterations]
    jnz .again
    mov dx,passed
    mov ah,9
    int 0x21
    mov ax,0x4c00
    int 0x21
fail:
    mov dx,failed
    mov ah,9
    int 0x21
    mov ax,0x4c01
    int 0x21
segment _DATA public class=DATA use16
    times 32 db 0
handle dw 0
iterations dw 0
info times 66 db 0
passed db 'WIN16 MMIO_BUFFER PASS',13,10,'$'
failed db 'WIN16 MMIO_BUFFER FAIL',13,10,'$'
segment STACK stack class=STACK use16
    resb 8192
group DGROUP _DATA STACK
