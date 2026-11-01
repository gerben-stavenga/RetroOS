bits 16
segment _TEXT public class=CODE use16
extern InitTask, DOS3Call, _lcreat, _lwrite, _lread, _lclose
global _start
_start:
    mov byte [stage],'0'
    call far InitTask
    test ax,ax
    jz fail
    ; InitTask must receive the command tail passed through the native PSP.
    cmp byte [es:bx],0
    je .tail_ok
    cmp dword [es:bx],'prob'
    jne fail
    cmp byte [es:bx+4],'e'
    jne fail
.tail_ok:
    mov [initial_sp],sp
    ; Wine creates and writes; direct DOS seeks the same handle.
    push ds
    push word filename
    push word 0
    mov byte [stage],'1'
    call far _lcreat
    cmp ax,0xffff
    je fail
    mov [handle],ax
    push ax
    push ds
    push word payload
    push word 4
    mov byte [stage],'2'
    call far _lwrite
    cmp ax,4
    jne fail
    mov bx,[handle]
    xor cx,cx
    xor dx,dx
    mov ax,0x4202
    mov byte [stage],'3'
    int 0x21
    jc fail
    cmp ax,4
    jne fail
    test dx,dx
    jnz fail
    ; Wine's register-entry DOS API reaches that same native DOS service.
    mov bx,[handle]
    xor cx,cx
    xor dx,dx
    mov ax,0x4200
    mov byte [stage],'4'
    call far DOS3Call
    jc fail
    test ax,ax
    jnz fail
    push word [handle]
    push ds
    push word buffer
    push word 4
    mov byte [stage],'5'
    call far _lread
    cmp ax,4
    jne fail
    cmp dword [buffer],0x54534554
    jne fail
    ; DOS closes a Wine handle. Reopen in DOS and close through Wine.
    mov bx,[handle]
    mov ah,0x3e
    mov byte [stage],'6'
    int 0x21
    jc fail
    mov dx,filename
    mov ax,0x3d00
    mov byte [stage],'7'
    call far DOS3Call
    jc fail
    mov [handle],ax
    push ax
    push ds
    push word buffer
    push word 4
    mov byte [stage],'8'
    call far _lread
    cmp ax,4
    jne fail
    cmp dword [buffer],0x54534554
    jne fail
    push word [handle]
    mov byte [stage],'9'
    call far _lclose
    test ax,ax
    jnz fail
    ; Both entry paths reject the now-closed native descriptor.
    mov bx,[handle]
    mov ax,0x4201
    xor cx,cx
    xor dx,dx
    mov byte [stage],'A'
    call far DOS3Call
    jnc fail
    cmp ax,6
    jne fail
    cmp sp,[initial_sp]
    jne fail
    mov dx,passed
    mov ah,9
    mov byte [stage],'B'
    int 0x21
    mov ax,0x4c00
    mov byte [stage],'C'
    int 0x21
fail:
    mov dx,failed
    mov ah,9
    int 0x21
    mov ax,0x4c01
    int 0x21
segment _DATA public class=DATA use16
    times 32 db 0                 ; Win16 INSTANCEDATA lives at DS:0
initial_sp: dw 0
handle: dw 0
filename: db 'DOSFILE.TMP',0
payload: db 'TEST'
buffer: dd 0
passed: db 'WIN16 DOS_FILES PASS',13,10,'$'
failed: db 'WIN16 DOS_FILES FAIL stage '
stage: db '0',13,10,'$'
segment STACK stack class=STACK use16
    resb 8192
group DGROUP _DATA STACK
