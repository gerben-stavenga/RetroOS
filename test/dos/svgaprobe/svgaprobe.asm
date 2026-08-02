; SVGAPROBE.COM — VBE/SVGA conformance probe.
;
; Exercises 4F00 controller info, every advertised mode-info record, 4F02/03
; mode set/get, 4F05 bank persistence, 4F09 palette round-trip, and the LFB
; metadata used by protected-mode clients. Verdicts go through DOS stdout so
; the kernel's console mirror makes them assertable in hosted CI.

        bits 16
        org 0x100

start:
        push cs
        pop ds
        push cs
        pop es

        mov dword [ctrl], 'VBE2'
        mov ax, 0x4F00
        mov di, ctrl
        int 0x10
        cmp ax, 0x004F
        jne fail_info
        cmp byte [ctrl], 'V'
        jne fail_info
        cmp byte [ctrl + 1], 'E'
        jne fail_info
        cmp byte [ctrl + 2], 'S'
        jne fail_info
        cmp byte [ctrl + 3], 'A'
        jne fail_info
        cmp word [ctrl + 4], 0x0200
        jb fail_info
        cmp word [ctrl + 0x12], 1
        jb fail_info
        mov dx, ok_info
        call emit

        mov si, modes
.mode_loop:
        mov cx, [si]
        or cx, cx
        jz .modes_done
        mov ax, 0x4F01
        mov di, mode_info
        int 0x10
        cmp ax, 0x004F
        jne fail_modes
        mov ax, [mode_info]
        and ax, 0x0091                 ; supported, graphics, LFB
        cmp ax, 0x0091
        jne fail_modes
        mov ax, [si + 2]
        cmp [mode_info + 0x12], ax
        jne fail_modes
        mov ax, [si + 4]
        cmp [mode_info + 0x14], ax
        jne fail_modes
        mov al, [si + 6]
        cmp [mode_info + 0x19], al
        jne fail_modes
        mov al, [si + 7]
        cmp [mode_info + 0x1B], al
        jne fail_modes
        cmp dword [mode_info + 0x28], 0
        je fail_lfb
        cmp word [mode_info + 0x32], 0
        je fail_lfb
        add si, 8
        jmp .mode_loop
.modes_done:
        mov dx, ok_modes
        call emit
        mov dx, ok_lfb
        call emit

        ; Bank 1 must retain its contents across a bank-0 round trip.
        mov ax, 0x4F02
        mov bx, 0x0103                 ; 800x600x8, banked
        int 0x10
        cmp ax, 0x004F
        jne fail_bank
        mov ax, 0x4F03
        int 0x10
        cmp ax, 0x004F
        jne fail_bank
        and bx, 0x01FF
        cmp bx, 0x0103
        jne fail_bank
        mov ax, 0x4F05
        xor bx, bx
        mov dx, 1
        int 0x10
        cmp ax, 0x004F
        jne fail_bank
        push es
        mov ax, 0xA000
        mov es, ax
        mov byte [es:0], 0x5A
        pop es
        mov ax, 0x4F05
        xor bx, bx
        xor dx, dx
        int 0x10
        mov ax, 0x4F05
        xor bx, bx
        mov dx, 1
        int 0x10
        push es
        mov ax, 0xA000
        mov es, ax
        cmp byte [es:0], 0x5A
        pop es
        jne fail_bank
        mov ax, 0x4F05                 ; get current window
        mov bx, 0x0100
        int 0x10
        cmp dx, 1
        jne fail_bank
        mov dx, ok_bank
        call emit

        ; Palette entry 7: VBE tables are B,G,R,reserved, six-bit channels.
        mov byte [palette], 3
        mov byte [palette + 1], 17
        mov byte [palette + 2], 55
        mov byte [palette + 3], 0
        mov ax, 0x4F09
        xor bx, bx
        mov cx, 1
        mov dx, 7
        mov di, palette
        int 0x10
        cmp ax, 0x004F
        jne fail_palette
        mov dword [palette], 0
        mov ax, 0x4F09
        mov bx, 1
        mov cx, 1
        mov dx, 7
        mov di, palette
        int 0x10
        cmp ax, 0x004F
        jne fail_palette
        cmp byte [palette], 3
        jne fail_palette
        cmp byte [palette + 1], 17
        jne fail_palette
        cmp byte [palette + 2], 55
        jne fail_palette
        mov dx, ok_palette
        call emit

        ; Stay in a direct-colour LFB mode while waiting. Besides leaving the
        ; probe inspectable, this lets the host-side F12 regression take a
        ; native SVGA owner and verify detach/restore rather than only taking
        ; legacy text VGA.
        mov ax, 0x4F02
        mov bx, 0x4112                 ; 640x480x24, linear framebuffer
        int 0x10
        cmp ax, 0x004F
        jne fail_lfb
        mov ax, 0x4F03
        int 0x10
        cmp ax, 0x004F
        jne fail_lfb
        and bx, 0x3FFF
        cmp bx, 0x0112
        jne fail_lfb
        mov dx, ok_all
        call emit
        xor ah, ah                      ; keep CI's guest alive; key exits manually
        int 0x16
        mov ax, 3
        int 0x10
        mov ax, 0x4C00
        int 0x21

fail_info:    mov dx, bad_info
              jmp fail
fail_modes:   push cx
              mov dx, bad_mode_num
              call emit
              pop ax
              call emit_hex16
              mov dx, newline
              call emit
              mov dx, bad_modes
              jmp fail
fail_lfb:     mov dx, bad_lfb
              jmp fail
fail_bank:    mov dx, bad_bank
              jmp fail
fail_palette: mov dx, bad_palette
fail:
        push dx
        mov ax, 3
        int 0x10
        pop dx
        call emit
        mov ax, 0x4C01
        int 0x21

emit:
        mov ah, 9
        int 0x21
        ret

emit_hex16:
        push ax
        push bx
        push cx
        push dx
        mov bx, ax
        mov cx, 4
.digit:
        rol bx, 4
        mov dl, bl
        and dl, 0x0F
        add dl, '0'
        cmp dl, '9'
        jbe .put
        add dl, 7
.put:   mov ah, 2
        int 0x21
        loop .digit
        pop dx
        pop cx
        pop bx
        pop ax
        ret

ok_info:      db 'VBE-INFO-OK', 13, 10, '$'
ok_modes:     db 'VBE-MODES-OK', 13, 10, '$'
ok_lfb:       db 'VBE-LFB-OK', 13, 10, '$'
ok_bank:      db 'VBE-BANK-OK', 13, 10, '$'
ok_palette:   db 'VBE-PAL-OK', 13, 10, '$'
ok_all:       db 'VBE-ALL-OK', 13, 10, '$'
bad_info:     db 'VBE-INFO-FAIL', 13, 10, '$'
bad_modes:    db 'VBE-MODES-FAIL', 13, 10, '$'
bad_lfb:      db 'VBE-LFB-FAIL', 13, 10, '$'
bad_bank:     db 'VBE-BANK-FAIL', 13, 10, '$'
bad_palette:  db 'VBE-PAL-FAIL', 13, 10, '$'
bad_mode_num: db 'VBE-MODE-FAIL mode=', '$'
newline:      db 13, 10, '$'

align 4
; mode, width, height, bpp, memory model
modes:
        dw 0x101, 640, 480
        db 8, 4
        dw 0x103, 800, 600
        db 8, 4
        dw 0x110, 640, 480
        db 15, 6
        dw 0x111, 640, 480
        db 16, 6
        dw 0x112, 640, 480
        db 24, 6
        dw 0

align 4
palette:   times 4 db 0
ctrl:      times 256 db 0
mode_info: times 256 db 0
