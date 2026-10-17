; DOS file APIs must reach the same SMB VFS mount as Linux.
org 100h
bits 16
    mov dx,path
    xor cx,cx
    mov ah,3ch
    int 21h
    jc fail_open
    mov bx,ax
    mov dx,message
    mov cx,message_end-message
    mov ah,40h
    int 21h
    jc fail_write
    cmp ax,message_end-message
    jne fail_write
    mov ah,3eh
    int 21h
    jc fail_close
    mov ax,4c00h
    int 21h
fail_open:
    mov ax,4c31h
    int 21h
fail_write:
    mov ax,4c32h
    int 21h
fail_close:
    mov ax,4c33h
    int 21h
path: db 'H:\DOS.TXT',0
message: db 'DOS through shared SMB VFS',13,10
message_end:
