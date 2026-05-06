; GFX.COM — Mode 13h test (320x200, 256 colors)
; Draws colored pixels + the letter 'A' rendered from the BIOS 8x8 CGA
; font at F000:FA6E, waits for keypress, then exits (PSP stub restores
; mode 3). The bitmap-render confirms whether the font ROM is reachable
; from a DOS process and whether direct A0000 writes show on screen.
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

    ; Render 'A' using the font pointed to by IVT[0x43] (linear 0x10C).
    ; IVT[0x43] is the BIOS "graphics-mode character generator" far ptr,
    ; set during mode-set to the font appropriate for the current mode
    ; (8x8 for mode 13h). Following it instead of hard-coding F000:FA6E
    ; tests whether SeaBIOS sets the vector and whether the target font
    ; is reachable from a DOS process.
    push ds
    xor ax, ax
    mov ds, ax                   ; DS = 0 (IVT segment)
    mov si, [0x10C]              ; offset of IVT[0x43] -> font_off
    mov ax, [0x10E]              ; segment of IVT[0x43] -> font_seg
    mov ds, ax                   ; DS:SI = font[0]
    add si, 'A'*8                ; advance to 'A' glyph (8 bytes per char)
    mov di, 80*320 + 80          ; framebuffer offset (es=0xA000 already)
    mov dx, 8                    ; rows
.fontrow:
    lodsb                        ; al = bitmap row byte
    push di
    mov cx, 8                    ; cols
.fontcol:
    shl al, 1                    ; bit 7 -> CF
    jnc .nopx
    mov byte [es:di], 15         ; white pixel
.nopx:
    inc di
    loop .fontcol
    pop di
    add di, 320                  ; advance one pixel-row
    dec dx
    jnz .fontrow
    pop ds

    ; Wait for keypress
    mov ah, 0x00
    int 0x16

    ; Restore text mode 3 before exiting
    mov ax, 0x0003
    int 0x10

    ; RET → PSP:0000 → INT 20h → exit_thread
    ret
