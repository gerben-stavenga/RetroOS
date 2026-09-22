bits 16
org 100h
start:
    mov ax, 3
    int 10h
    mov ax, 40h
    mov es, ax
    mov ah, 1
    mov cx, 0607h
    int 10h
    cmp word [es:60h], 0607h
    jne fail
    mov al, 0ah
    call read_crtc
    cmp al, 14
    jne fail
    mov al, 0bh
    call read_crtc
    cmp al, 15
    jne fail
    mov ah, 2
    xor bx, bx
    mov dx, 0911h
    int 10h
    cmp word [es:50h], 0911h
    jne fail
    mov cx, 9*80+17
    call check_cursor
    ; An inactive page changes its BDA entry, not the visible hardware cursor.
    mov ah, 2
    mov bh, 1
    mov dx, 0203h
    int 10h
    cmp word [es:52h], 0203h
    jne fail
    mov cx, 9*80+17
    call check_cursor
    mov ax, 0501h
    int 10h
    cmp byte [es:62h], 1
    jne fail
    cmp word [es:4eh], 1000h
    jne fail
    mov cx, 0800h+2*80+3
    call check_cursor
    mov al, 0ch
    call read_crtc
    cmp al, 8
    jne fail
    mov ax, 0500h
    int 10h
    mov cx, 9*80+17
    call check_cursor
    ; Hide and restore the cursor, including the BDA shape.
    mov ah, 1
    mov cx, 2000h
    int 10h
    mov al, 0ah
    call read_crtc
    test al, 20h
    jz fail
    mov dx, passed
    mov ah, 9
    int 21h
    ; Blank screen: the only white pixels must be the cursor at row 9, col 17.
    mov ax, 0b800h
    mov es, ax
    xor di, di
    mov ax, 1f20h
    mov cx, 80*25
    rep stosw
    mov ah, 1
    mov cx, 0607h
    int 10h
    mov ah, 2
    xor bx, bx
    mov dx, 0911h
    int 10h
.wait:
    hlt
    jmp .wait
read_crtc:
    mov dx, 3d4h
    out dx, al
    inc dx
    in al, dx
    ret
check_cursor:
    mov al, 0eh
    call read_crtc
    cmp al, ch
    jne fail
    mov al, 0fh
    call read_crtc
    cmp al, cl
    jne fail
    ret
fail:
    mov dx, failed
    mov ah, 9
    int 21h
    mov ax, 4c01h
    int 21h
passed db 'CURSOR-PROBE-PASS',13,10,'$'
failed db 'CURSOR-PROBE-FAIL',13,10,'$'
