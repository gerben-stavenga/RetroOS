; GFX.COM — Mode 13h test (320x200, 256 colors)
; Draws colored pixels, waits for keypress, then exits (PSP stub restores mode 3)
org 0x100

    ; Switch to mode 13h
    mov ax, 0x0013
    int 0x10

    ; ES:DI → framebuffer at A000:0000
    mov ax, 0xA000
    mov es, ax

    ; Draw horizontal color bars (200 rows, 320 cols)
    xor di, di
    mov cx, 200          ; rows
.row:
    push cx
    mov cx, 320          ; cols
    mov al, 200
    sub al, [esp]        ; color = row number (0-199)
.col:
    stosb
    loop .col
    pop cx
    loop .row

    ; Draw a white diagonal line
    xor bx, bx          ; y = 0
.diag:
    mov ax, bx
    mov cx, 320
    mul cx               ; ax = y * 320
    add ax, bx           ; ax = y * 320 + x (x == y)
    mov di, ax
    mov byte [es:di], 15 ; white
    inc bx
    cmp bx, 200
    jb .diag

    ; Wait for keypress
    xor ax, ax
    int 0x16

    ; Restore text mode 3 before exiting
    mov ax, 0x0003
    int 0x10

    ; RET → PSP:0000 → INT 20h
    ret
