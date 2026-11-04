; VGA reads/writes must agree; BIOS text services must use kernel VRAM.
bits 16
org 100h

    mov ax, 3
    int 10h
    ; VChess's VGA probe disables odd/even reads, keeps odd/even writes,
    ; then checks a rotated OR against the byte loaded into the VGA latches.
    mov dx, 3c4h
    mov ax, 0102h
    out dx, ax
    mov dl, 0ceh
    mov ax, 0005h
    out dx, ax
    mov ax, 0004h
    out dx, ax
    mov ax, 0ba00h
    mov es, ax
    mov al, 1
    mov [es:0], al
    cmp [es:0], al
    jne fail
    mov ax, 1103h
    out dx, ax
    mov byte [es:0], 0a0h
    cmp byte [es:0], 51h
    jne fail

    mov ax, 3
    int 10h
    mov ax, 0b800h
    mov es, ax
    xor di, di
    mov ax, 0741h
    mov cx, 2000
    rep stosw
    mov word [es:160], 0742h

    ; Keep text geometry, but enable both odd/even plane pairs. This legal
    ; register change prevents a direct guest mapping of the VGA CPU view.
    mov dx, 3c4h
    mov ax, 0f02h
    out dx, ax

    ; Cursor save/restore must use the same backing while B800 is trapped.
    xor ax, ax
    int 33h
    mov ax, 1
    int 33h
    mov ax, 4
    mov cx, 8
    xor dx, dx
    int 33h
    mov ax, 2
    int 33h

    mov ah, 8
    xor bx, bx
    int 10h
    cmp ax, 0741h
    jne fail

    ; Scroll through both BIOS window services, then DOS teletype at row 24.
    mov ax, 0601h
    call window
    mov ax, 0701h
    call window
    mov ah, 2
    xor bx, bx
    mov dx, 1800h
    int 10h
    mov ah, 2
    mov dl, 10
    int 21h

    ; The original second row must now be the first row again.
    mov ah, 2
    xor bx, bx
    xor dx, dx
    int 10h
    mov ah, 8
    int 10h
    cmp ax, 0742h
    jne fail

    mov ax, 3
    int 10h
    mov dx, success
    mov ah, 9
    int 21h
    mov ax, 4c00h
    int 21h
window:
    mov bh, 7
    xor cx, cx
    mov dx, 184fh
    int 10h
    ret
fail:
    mov ax, 3
    int 10h
    mov dx, failure
    mov ah, 9
    int 21h
    mov ax, 4c01h
    int 21h
success db 'VGA-TEXT PASS', 13, 10, '$'
failure db 'VGA-TEXT FAIL', 13, 10, '$'
