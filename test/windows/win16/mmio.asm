bits 16
segment _TEXT public class=CODE use16
extern Debug, Exit, mmioOpen, mmioClose, mmioRead, mmioWrite, mmioSeek
extern mmioGetInfo, mmioSetInfo, mmioAdvance, mmioDescend, mmioAscend, mmioCreateChunk
extern IsBadReadPtr
%macro check_zero 0
    test ax,ax
    jnz fail
%endmacro
%macro get_info 0
    push word [handle]
    push ds
    push word info
    push word 0
    call far mmioGetInfo
    check_zero
%endmacro
%macro open_file 1
    push ds
    push word filename
    push ds
    push word info
    push dword %1
    call far mmioOpen
    test ax,ax
    jz fail
    mov [handle],ax
%endmacro
%macro seek_start 0
    push word [handle]
    push dword 0
    push word 0
    call far mmioSeek
    or ax,dx
    jnz fail
%endmacro
global _start
_start:
    mov [initial_sp],sp
    mov dword [info+16],7
    open_file 0x11002
    mov dword [root+8],'TEST'
    push word [handle]
    push ds
    push word root
    push word 0x20
    call far mmioCreateChunk
    check_zero
    mov dword [chunk],'data'
    push word [handle]
    push ds
    push word chunk
    push word 0
    call far mmioCreateChunk
    check_zero
    push word [handle]
    push ds
    push word payload
    push dword 5
    call far mmioWrite
    cmp ax,5
    jne fail
    push word [handle]
    push ds
    push word chunk
    push word 0
    call far mmioAscend
    check_zero
    cmp dword [chunk+4],5
    jne fail
    push word [handle]
    push ds
    push word root
    push word 0
    call far mmioAscend
    check_zero
    cmp dword [root+4],18
    jne fail
    get_info
    mov eax,[info+20]
    mov [buffer_pointer],eax
    push word [handle]
    push word 1
    call far mmioClose
    cmp ax,11
    jne fail
    push dword [buffer_pointer]
    push word 1
    call far IsBadReadPtr
    check_zero
    push word [handle]
    push word 0
    call far mmioClose
    check_zero
    push dword [buffer_pointer]
    push word 1
    call far IsBadReadPtr
    cmp ax,1
    jne fail
    call clear_info
    mov dword [info+16],7
    open_file 0x10000
    get_info
    cmp dword [info+16],7
    jne fail
    mov eax,[info+32]
    sub eax,[info+20]
    cmp eax,7
    jne fail
    push word [handle]
    push ds
    push word info
    push word 0
    call far mmioAdvance
    check_zero
    les bx,[info+20]
    cmp dword [es:bx],'RIFF'
    jne fail
    push ds
    pop es
    add word [info+24],3
    push word [handle]
    push ds
    push word info
    push word 0
    call far mmioSetInfo
    check_zero
    push word [handle]
    push dword 0
    push word 1
    call far mmioSeek
    cmp ax,3
    jne fail
    seek_start
    mov dword [root+8],'TEST'
    push word [handle]
    push ds
    push word root
    push dword 0
    push word 0x20
    call far mmioDescend
    check_zero
    mov dword [chunk],'data'
    push word [handle]
    push ds
    push word chunk
    push ds
    push word root
    push word 0x10
    call far mmioDescend
    check_zero
    cmp dword [chunk+4],5
    jne fail
    push word [handle]
    push ds
    push word output
    push dword 5
    call far mmioRead
    cmp ax,5
    jne fail
    cmp dword [output],'hell'
    jne fail
    cmp byte [output+4],'o'
    jne fail
    push word [handle]
    push word 0
    call far mmioClose
    check_zero
    call clear_info
    push ds
    push word missing
    push ds
    push word info
    push dword 0x10000
    call far mmioOpen
    check_zero
    cmp word [info+12],257
    jne fail
    mov word [iterations],100
.reopen:
    call clear_info
    open_file 0x10000
    push word [handle]
    push word 0
    call far mmioClose
    check_zero
    dec word [iterations]
    jnz .reopen
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
clear_info:
    push es
    push di
    push cx
    push ds
    pop es
    mov di,info
    xor ax,ax
    mov cx,33
    cld
    rep stosw
    pop cx
    pop di
    pop es
    ret
segment _DATA public class=DATA use16
initial_sp dw 0
handle dw 0
iterations dw 0
buffer_pointer dd 0
info times 66 db 0
root times 5 dd 0
chunk times 5 dd 0
payload db 'hello'
output times 8 db 0
filename db 'MMIO16.RIF',0
missing db 'MMIONONE.RIF',0
passed db 'WIN16 MMIO PASS',0
failed db 'WIN16 MMIO FAIL',0
segment STACK stack class=STACK use16
    resb 8192
group DGROUP _DATA STACK
