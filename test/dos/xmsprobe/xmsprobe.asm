; XMSPROBE.COM — exercises the XMS 3.0 handle, move, lock, extended-memory,
; no-HMA/A20, and UMB contracts implemented by RetroOS.
bits 16
org 100h

%macro xcall 1
    mov ah, %1
    call far [xms_entry]
%endmacro

start:
    push cs
    pop ds
    mov ax, 4300h
    int 2fh
    cmp al, 80h
    jne fail
    mov ax, 4310h
    int 2fh
    mov [xms_entry], bx
    mov [xms_entry+2], es

    mov byte [stage], '1'
    xcall 00h
    cmp ax, 0300h
    jne fail
    cmp dx, 0
    jne fail
    xcall 01h
    cmp ax, 0
    jne fail
    cmp bl, 90h
    jne fail
    xcall 03h
    cmp ax, 0
    jne fail
    cmp bl, 82h
    jne fail
    xcall 04h
    cmp ax, 1
    jne fail
    xcall 07h
    cmp ax, 0
    jne fail

    ; Zero-length EMBs are legal and still consume a handle.
    mov byte [stage], '2'
    xor dx, dx
    xcall 09h
    cmp ax, 1
    jne fail
    mov [zero_handle], dx
    xcall 0eh
    cmp ax, 1
    jne fail
    cmp dx, 0
    jne fail
    cmp bh, 0
    jne fail
    mov dx, [zero_handle]
    xcall 0dh
    cmp ax, 0
    jne fail
    cmp bl, 0aah
    jne fail
    mov dx, [zero_handle]
    xcall 0ah
    cmp ax, 1
    jne fail

    ; Counted locks protect a block from free and resize.
    mov byte [stage], '3'
    mov dx, 4
    xcall 09h
    cmp ax, 1
    jne fail
    mov [data_handle], dx
    xcall 0ch
    cmp ax, 1
    jne fail
    mov dx, [data_handle]
    xcall 0ch
    cmp ax, 1
    jne fail
    mov dx, [data_handle]
    xcall 0eh
    cmp bh, 2
    jne fail
    mov dx, [data_handle]
    mov bx, 8
    xcall 0fh
    cmp ax, 0
    jne fail
    cmp bl, 0abh
    jne fail
    mov dx, [data_handle]
    xcall 0ah
    cmp ax, 0
    jne fail
    cmp bl, 0abh
    jne fail
    mov dx, [data_handle]
    xcall 0dh
    cmp ax, 1
    jne fail
    mov dx, [data_handle]
    xcall 0dh
    cmp ax, 1
    jne fail
    mov dx, [data_handle]
    xcall 0dh
    cmp ax, 0
    jne fail
    cmp bl, 0aah
    jne fail

    ; Move conventional -> EMB -> conventional and reject an odd length.
    mov byte [stage], '4'
    mov word [move_desc+6], source
    mov word [move_desc+8], ds
    mov ax, [data_handle]
    mov [move_desc+10], ax
    mov si, move_desc
    xcall 0bh
    cmp ax, 1
    jne fail
    mov ax, [data_handle]
    mov [move_desc+4], ax
    mov dword [move_desc+6], 0
    mov word [move_desc+10], 0
    mov word [move_desc+12], destination
    mov word [move_desc+14], ds
    mov si, move_desc
    xcall 0bh
    cmp ax, 1
    jne fail
    mov eax, [source]
    cmp eax, [destination]
    jne fail
    mov dword [move_desc], 1
    mov si, move_desc
    xcall 0bh
    cmp ax, 0
    jne fail
    cmp bl, 0a7h
    jne fail

    ; 386-width information and resize calls use the same handle pool.
    mov byte [stage], '5'
    mov dx, [data_handle]
    xcall 8eh
    cmp ax, 1
    jne fail
    cmp edx, 4
    jne fail
    mov dx, [data_handle]
    mov ebx, 8
    xcall 8fh
    cmp ax, 1
    jne fail
    mov dx, [data_handle]
    xcall 8eh
    cmp edx, 8
    jne fail
    mov dx, [data_handle]
    xcall 0ah
    cmp ax, 1
    jne fail
    mov edx, 4
    xcall 89h
    cmp ax, 1
    jne fail
    xcall 0ah
    cmp ax, 1
    jne fail

    ; Adjacent UMBs must remain separate allocations; 12h grows in place.
    mov byte [stage], '6'
    mov dx, 1
    xcall 10h
    cmp ax, 1
    jne fail
    mov [umb_one], bx
    mov dx, 1
    xcall 10h
    cmp ax, 1
    jne fail
    mov [umb_two], bx
    mov dx, [umb_one]
    xcall 11h
    cmp ax, 1
    jne fail
    mov dx, [umb_two]
    xcall 11h
    cmp ax, 1
    jne fail
    mov dx, 1
    xcall 10h
    cmp ax, 1
    jne fail
    mov [umb_one], bx
    mov dx, bx
    mov bx, 200h
    xcall 12h
    cmp ax, 1
    jne fail
    mov dx, [umb_one]
    xcall 11h
    cmp ax, 1
    jne fail

    mov dx, pass_msg
    mov ah, 09h
    int 21h
    mov ax, 4c00h
    int 21h

fail:
    mov dx, fail_msg
    mov ah, 09h
    int 21h
    mov dl, [stage]
    mov ah, 02h
    int 21h
    mov dx, newline
    mov ah, 09h
    int 21h
    mov ax, 4c01h
    int 21h

xms_entry   dw 0, 0
zero_handle dw 0
data_handle dw 0
umb_one     dw 0
umb_two     dw 0
stage       db '?'
source      db 'XMS!'
destination times 4 db 0
move_desc:
    dd 4
    dw 0
    dd 0
    dw 0
    dd 0
pass_msg db 'XMSPROBE PASS', 13, 10, '$'
fail_msg db 'XMSPROBE FAIL stage ', '$'
newline  db 13, 10, '$'
