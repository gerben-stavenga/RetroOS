; SBDOOR.COM — DSP stream-continuity exercise (manual tool, not CI: its
; timing phases are real-time and too slow for the TCG engine).
;
; One 1618-byte block of loud square wave (~146 ms at 11 kHz), played:
;   phase 1: 10x chained back-to-back — restart the moment the 8237 status
;            TC bit shows completion (ISR-chain style, PoP's gate grinding).
;            A clean pipeline yields ~1.5 s of continuous tone; seam gaps
;            are emulation-side stutter.
;   phase 2: 10x re-triggered every 3 BIOS ticks (~165 ms) with PoP's
;            stop routine (wait-busy, wait-idle, DSP 0xD0) first.
;
; Listen on metal / capture with --wav; the stream-hold hangover (vsb.rs)
; records the inter-sample gaps as real silence.
        org 0x100
start:
        ; DSP reset
        mov dx, 0x226
        mov al, 1
        out dx, al
        mov cx, 100
.rst:   loop .rst
        xor al, al
        out dx, al
        mov cx, 0xFFFF
.aa:    mov dx, 0x22E
        in  al, dx
        test al, 0x80
        jz  .aan
        mov dx, 0x22A
        in  al, dx
        cmp al, 0xAA
        je  .ok
.aan:   loop .aa
        jmp done
.ok:
        mov dx, 0x22C          ; speaker on
        mov al, 0xD1
        out dx, al

        ; ---- phase 1: chained on TC ----
        mov word [iter], 10
p1loop:
        call startblk
        mov bx, 0x2000         ; bounded TC poll
.tcwait:
        mov cx, 0x0100
.tcin:  in  al, 0x08
        test al, 0x02
        jnz .tcdone
        loop .tcin
        dec bx
        jnz .tcwait
.tcdone:
        dec word [iter]
        jnz p1loop

        ; ---- gap marker: ~0.5 s of silence (9 BIOS ticks) ----
        mov cx, 9
        call tickwait

        ; ---- phase 2: re-trigger every 3 ticks with PoP stop first ----
        mov word [iter], 10
p2loop:
        call startblk
        mov cx, 3
        call tickwait
        ; PoP stop: wait busy, wait idle, pause
        mov dx, 0x22C
        mov cx, 0xFFFF
.wb:    in  al, dx
        test al, 0x80
        jnz .wi
        loop .wb
        jmp .p2n
.wi:    mov cx, 0xFFFF
.wi2:   in  al, dx
        test al, 0x80
        jz  .stp
        loop .wi2
        jmp .p2n
.stp:   mov al, 0xD0
        out dx, al
.p2n:
        dec word [iter]
        jnz p2loop
done:
        mov ax, 0x4C00
        int 0x21

; start one 1618-byte single-cycle block at buf
startblk:
        mov al, 0x05
        out 0x0A, al           ; mask ch1
        mov al, 0x49
        out 0x0B, al           ; mode: single, read, ch1
        xor al, al
        out 0x0C, al           ; clear flip-flop
        mov ax, cs
        mov bx, ax
        shr bx, 12
        shl ax, 4
        add ax, buf
        adc bx, 0
        out 0x02, al
        mov al, ah
        out 0x02, al
        mov ax, bx
        out 0x83, al           ; page
        mov ax, 1617
        out 0x03, al
        mov al, ah
        out 0x03, al
        mov al, 0x01
        out 0x0A, al           ; unmask ch1
        mov dx, 0x22C
        mov al, 0x40
        out dx, al
        mov al, 0xA6
        out dx, al
        mov al, 0x14
        out dx, al
        mov al, 0x51           ; 1617 & 0xFF
        out dx, al
        mov al, 0x06           ; 1617 >> 8
        out dx, al
        ret

; wait CX BIOS ticks (INT 1A AH=00, DX low word)
tickwait:
        push cx
        mov ah, 0
        int 0x1A
        mov bx, dx
        pop cx
.tw:    push cx
        mov ah, 0
        int 0x1A
        pop cx
        cmp dx, bx
        je  .tw
        mov bx, dx
        loop .tw
        ret

iter:   dw 0
buf:
%rep 202
        db 0xE0,0xE0,0xE0,0xE0, 0x20,0x20,0x20,0x20
%endrep
        db 0xE0,0xE0
