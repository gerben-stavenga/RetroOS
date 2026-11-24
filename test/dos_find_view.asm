; Capture the DOS FindFirst/FindNext view used by file managers.
bits 16
org 100h
    mov ah,3ch
    xor cx,cx
    mov dx,output
    int 21h
    jc fail
    mov [handle],ax
    mov ah,1ah
    mov dx,dta
    int 21h

    mov cx,10h                   ; directories and ordinary files
    call scan
    mov cx,16h                   ; include hidden and system files
    call scan

    mov bx,[handle]
    mov ah,3eh
    int 21h
    jc fail
    mov ax,4c00h
    int 21h

scan:
    mov ah,4eh
    mov dx,pattern
    int 21h
.next:
    jc .end
    call write_result
    mov ah,4fh
    int 21h
    jmp .next
.end:
    mov byte [dta+30],0          ; empty name separates the two searches
write_result:
    mov ah,40h
    mov bx,[handle]
    mov cx,22
    mov dx,dta+21
    int 21h
    jc fail
    cmp ax,cx
    jne fail
    ret

fail:
    mov ax,4c01h
    int 21h

output db 'C:\DNVIEW.DAT',0
pattern db 'C:\ITEMS\*.*',0
handle dw 0
dta times 43 db 0
