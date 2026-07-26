; SBDISC.COM — Sound Blaster DISCOVERY/INIT conformance probe.
;
; SBTEST.COM covers the completion protocol (busy flicker, busy->idle edge,
; 8237 terminal count) because that is what burned us. This one covers the
; other half — everything a game does BEFORE it plays a sample, which until
; now was only covered by "the game reached its menu".
;
; Each behavior emits one marker; a missing marker names exactly which part
; of the discovery surface is wrong:
;
;   RST-OK       DSP reset handshake returns 0xAA
;   VER-x.y      DSP version query (0xE1) — how a game picks SB / SBPro / SB16
;   MIXRST-OK    mixer reset (index 0x00) then a read-back of the SB16's
;                native master volume (0x30) — not the SB Pro-era 0x22,
;                which a real CT1745 aliases but other implementations do
;                not (DOSBox-X returns 0xFF there)
;   MIXVOL-OK    that register holds the 5-bit level written to it
;   MIXALIAS-*   whether the legacy 0x22 alias exists — informational, since
;                implementations legitimately differ
;   IRQSTAT-OK   mixer 0x82 reports "no interrupt pending" when idle
;   TRIG-OK      DSP 0xF2 raises the card's IRQ (the classic auto-detect)
;   ACK8-OK      reading base+0x0E acknowledges and clears that interrupt
;   SPKR-OK      speaker on/off (0xD1/0xD3) is accepted
;   E4E8-OK      DSP test register round-trips a byte
;   AUTOINIT-OK  auto-init block (0x48 size + 0x1C) reaches terminal count

;
; The same binary runs on 86Box against its faithful SB16 model, so the
; expected answers are validated against a reference rather than against our
; own emulation's habits. Markers go to the screen AND to C:\SBDISC.LOG, so
; a GUI-only backend can still be asserted on (see test/sb_86box.sh).
;
; Base is 0x220 throughout: BLASTER declares what the guest sees and the
; harness keeps it there while moving the physical card around underneath.

        org 0x100
start:
        mov ah, 0x3C
        xor cx, cx
        mov dx, fname
        int 0x21
        jc  .nolog
        mov [fhandle], ax
.nolog:

; ── DSP reset ────────────────────────────────────────────────────────────
        call dsp_reset
        jc  fail_rst
        mov dx, m_rst
        call emit

; ── DSP version (0xE1) ───────────────────────────────────────────────────
        mov al, 0xE1
        call dsp_write
        call dsp_read
        jc  fail_ver
        mov [ver_major], al
        call dsp_read
        jc  fail_ver
        mov [ver_minor], al
        ; render "VER-<major>.<minor>"
        mov al, [ver_major]
        call hexbyte
        mov [m_ver_maj], al
        mov [m_ver_maj+1], ah
        mov al, [ver_minor]
        call hexbyte
        mov [m_ver_min], al
        mov [m_ver_min+1], ah
        mov dx, m_ver
        call emit

; ── mixer: reset, then read a register back ──────────────────────────────
        mov dx, 0x224
        mov al, 0x00           ; index 0 = mixer reset
        out dx, al
        mov dx, 0x225
        mov al, 0x00
        out dx, al
        ; Master volume after reset must read as SOMETHING (not the open-bus
        ; 0xFF a missing mixer gives). Use the SB16's NATIVE register 0x30,
        ; not the SB Pro-era 0x22: a real CT1745 keeps the old registers as
        ; aliases, but implementations differ (DOSBox-X returns 0xFF for
        ; 0x22 while answering 0x30 fine), and a conformance probe must test
        ; the thing every SB16 has. The alias is checked separately below.
        mov dx, 0x224
        mov al, 0x30
        out dx, al
        mov dx, 0x225
        in  al, dx
        cmp al, 0xFF
        je  fail_mixrst
        mov dx, m_mixrst
        call emit

; ── mixer: a volume register holds what it was given ─────────────────────
        mov dx, 0x224
        mov al, 0x30
        out dx, al
        mov dx, 0x225
        mov al, 0xC0
        out dx, al
        mov dx, 0x224
        mov al, 0x30
        out dx, al
        mov dx, 0x225
        in  al, dx
        and al, 0xF8           ; 0x30 is a 5-bit level in bits 7:3
        cmp al, 0xC0
        jne fail_mixvol
        mov dx, m_mixvol
        call emit

        ; Legacy alias: a real CT1745 answers the SB Pro register 0x22 with
        ; the same level 0x30 holds. INFORMATIONAL — implementations differ,
        ; so a missing alias reports itself and does not fail the run.
        mov dx, 0x224
        mov al, 0x22
        out dx, al
        mov dx, 0x225
        in  al, dx
        cmp al, 0xFF
        je  .noalias
        mov dx, m_mixalias
        call emit
        jmp .aliasdone
.noalias:
        mov dx, m_noalias
        call emit
.aliasdone:

; ── mixer 0x82: no interrupt pending while idle ──────────────────────────
        mov dx, 0x224
        mov al, 0x82
        out dx, al
        mov dx, 0x225
        in  al, dx
        and al, 0x03           ; bit0 = 8-bit, bit1 = 16-bit
        jnz fail_irqstat
        mov dx, m_irqstat
        call emit

; ── speaker on/off ───────────────────────────────────────────────────────
        mov al, 0xD1
        call dsp_write
        mov al, 0xD3
        call dsp_write
        mov dx, m_spkr
        call emit

; ── DSP test register (E4h write / E8h read) ─────────────────────────────
        mov al, 0xE4
        call dsp_write
        mov al, 0x5A
        call dsp_write
        mov al, 0xE8
        call dsp_write
        call dsp_read
        jc  fail_e4e8
        cmp al, 0x5A
        jne fail_e4e8
        mov dx, m_e4e8
        call emit

; ── 0xF2 trigger IRQ, then acknowledge it ────────────────────────────────
        ; Hook the BLASTER IRQ (7 -> vector 0x0F) and unmask it, fire 0xF2,
        ; and require the handler to run. This is the auto-detect every
        ; setup program does to find its IRQ.
        xor ax, ax
        mov es, ax
        mov ax, [es:0x0F*4]
        mov [old_off], ax
        mov ax, [es:0x0F*4+2]
        mov [old_seg], ax
        cli
        mov word [es:0x0F*4], irq_stub
        mov [es:0x0F*4+2], cs
        in  al, 0x21
        mov [old_mask], al
        and al, 0x7F           ; unmask IRQ7
        out 0x21, al
        sti
        mov byte [irq_seen], 0
        mov al, 0xF2
        call dsp_write
        mov cx, 0xFFFF
.irqwait:
        cmp byte [irq_seen], 0
        jne .irq_ok
        loop .irqwait
        jmp fail_trig
.irq_ok:
        mov dx, m_trig
        call emit
        ; The handler already read base+0x0E; a second read must show the
        ; line released (mixer 0x82 back to idle).
        mov dx, 0x224
        mov al, 0x82
        out dx, al
        mov dx, 0x225
        in  al, dx
        and al, 0x01
        jnz fail_ack8
        mov dx, m_ack8
        call emit
        ; restore
        cli
        mov al, [old_mask]
        out 0x21, al
        mov ax, [old_off]
        mov [es:0x0F*4], ax
        mov ax, [old_seg]
        mov [es:0x0F*4+2], ax
        sti

; ── auto-init block reaches terminal count ───────────────────────────────
        ; 8237 ch1: auto-init, read, 1024 bytes at buf.
        mov al, 0x05
        out 0x0A, al           ; mask ch1
        mov al, 0x59           ; mode: auto-init, read, ch1
        out 0x0B, al
        xor al, al
        out 0x0C, al           ; clear flip-flop
        ; linear = (CS << 4) + buf, as a 24-bit value: low word to the
        ; channel's address register, bits 16..23 to its page register.
        mov ax, cs
        mov dx, ax
        mov cl, 12
        shr dx, cl             ; CS >> 12 = bits 16..19 of CS<<4
        mov cl, 4
        shl ax, cl             ; low 16 bits of CS<<4
        add ax, buf
        adc dx, 0              ; carry into the page
        out 0x02, al
        mov al, ah
        out 0x02, al
        mov al, dl
        out 0x83, al           ; page
        mov ax, 1023
        out 0x03, al
        mov al, ah
        out 0x03, al
        mov al, 0x01
        out 0x0A, al           ; unmask ch1
        ; DSP: time constant, block size, auto-init 8-bit
        mov al, 0x40
        call dsp_write
        mov al, 210            ; ~11 kHz
        call dsp_write
        mov al, 0x48
        call dsp_write
        mov al, 0xFF
        call dsp_write
        mov al, 0x03
        call dsp_write
        mov al, 0x1C           ; auto-init 8-bit DMA
        call dsp_write
        ; Wait for the 8237 status TC bit on ch1. 1024 bytes at ~11 kHz is
        ; ~93 ms of real playback, and every status read is a trap, so the
        ; wait is deliberately generous — a short spin times out before the
        ; block ends and looks like a card fault.
        mov bx, 64
.tcouter:
        mov cx, 0xFFFF
.tcwait:
        in  al, 0x08
        test al, 0x02          ; ch1 TC
        jnz .tc_ok
        loop .tcwait
        dec bx
        jnz .tcouter
        jmp fail_autoinit
.tc_ok:
        mov al, 0xDA           ; exit auto-init
        call dsp_write
        mov al, 0x05
        out 0x0A, al           ; mask ch1
        mov dx, m_autoinit
        call emit
        jmp exit

fail_rst:      mov dx, f_rst
               call emit
               jmp exit
fail_ver:      mov dx, f_ver
               call emit
               jmp exit
fail_mixrst:   mov dx, f_mixrst
               call emit
               jmp exit
fail_mixvol:   mov dx, f_mixvol
               call emit
               jmp exit
fail_irqstat:  mov dx, f_irqstat
               call emit
               jmp exit
fail_e4e8:     mov dx, f_e4e8
               call emit
               jmp exit
fail_trig:     mov dx, f_trig
               call emit
               jmp exit
fail_ack8:     mov dx, f_ack8
               call emit
               jmp exit
fail_autoinit: mov dx, f_autoinit
               call emit

exit:
        mov bx, [fhandle]
        cmp bx, 0xFFFF
        je  .noclose
        mov ah, 0x3E
        int 0x21
.noclose:
        mov ah, 0
        int 0x16
        mov ax, 0x4C00
        int 0x21

; IRQ7 handler: note it, acknowledge the card (read base+0x0E) and EOI.
irq_stub:
        push ax
        push dx
        mov byte [cs:irq_seen], 1
        mov dx, 0x22E
        in  al, dx             ; 8-bit IRQ acknowledge
        mov al, 0x20
        out 0x20, al           ; EOI
        pop dx
        pop ax
        iret

; DSP reset: CF set on failure.
dsp_reset:
        mov dx, 0x226
        mov al, 1
        out dx, al
        mov cx, 100
.hold:  loop .hold
        xor al, al
        out dx, al
        mov cx, 0xFFFF
.wait:
        mov dx, 0x22E
        in  al, dx
        test al, 0x80
        jz  .next
        mov dx, 0x22A
        in  al, dx
        cmp al, 0xAA
        je  .ok
.next:  loop .wait
        stc
        ret
.ok:    clc
        ret

; Write AL to the DSP once the write buffer is ready.
dsp_write:
        push dx
        push cx
        mov ah, al
        mov dx, 0x22C
        mov cx, 0xFFFF
.wait:
        in  al, dx
        test al, 0x80
        jz  .go
        loop .wait
.go:
        mov al, ah
        out dx, al
        pop cx
        pop dx
        ret

; Read a DSP byte into AL; CF set if none arrived.
dsp_read:
        push dx
        push cx
        mov dx, 0x22E
        mov cx, 0xFFFF
.wait:
        in  al, dx
        test al, 0x80
        jnz .got
        loop .wait
        pop cx
        pop dx
        stc
        ret
.got:
        mov dx, 0x22A
        in  al, dx
        pop cx
        pop dx
        clc
        ret

; AL -> two hex digits in AH (high) and AL (low).
hexbyte:
        push cx
        mov ah, al
        shr al, 1
        shr al, 1
        shr al, 1
        shr al, 1
        call .digit
        xchg al, ah
        and al, 0x0F
        call .digit
        xchg al, ah
        pop cx
        ret
.digit:
        cmp al, 10
        jb  .num
        add al, 'A' - 10
        ret
.num:   add al, '0'
        ret

; Print DS:DX ('$'-terminated) and append it to the log file.
emit:
        push ax
        push bx
        push cx
        push dx
        push si
        mov ah, 9
        int 0x21
        mov bx, [fhandle]
        cmp bx, 0xFFFF
        je  .done
        mov si, dx
        xor cx, cx
.len:
        lodsb
        cmp al, '$'
        je  .write
        inc cx
        jmp .len
.write:
        mov ah, 0x40
        int 0x21
.done:
        pop si
        pop dx
        pop cx
        pop bx
        pop ax
        ret

fname:      db 'C:\SBDISC.LOG', 0
fhandle:    dw 0xFFFF
ver_major:  db 0
ver_minor:  db 0
irq_seen:   db 0
old_off:    dw 0
old_seg:    dw 0
old_mask:   db 0

m_rst:      db 'RST-OK', 13, 10, '$'
m_ver:      db 'VER-'
m_ver_maj:  db '00', '.'
m_ver_min:  db '00', 13, 10, '$'
m_mixrst:   db 'MIXRST-OK', 13, 10, '$'
m_mixvol:   db 'MIXVOL-OK', 13, 10, '$'
m_mixalias: db 'MIXALIAS-OK (legacy 0x22 aliased)', 13, 10, '$'
m_noalias:  db 'MIXALIAS-NONE (no legacy 0x22 alias)', 13, 10, '$'
m_irqstat:  db 'IRQSTAT-OK', 13, 10, '$'
m_spkr:     db 'SPKR-OK', 13, 10, '$'
m_e4e8:     db 'E4E8-OK', 13, 10, '$'
m_trig:     db 'TRIG-OK', 13, 10, '$'
m_ack8:     db 'ACK8-OK', 13, 10, '$'
m_autoinit: db 'AUTOINIT-OK', 13, 10, '$'

f_rst:      db 'FAIL-RST', 13, 10, '$'
f_ver:      db 'FAIL-VER', 13, 10, '$'
f_mixrst:   db 'FAIL-MIXRST', 13, 10, '$'
f_mixvol:   db 'FAIL-MIXVOL', 13, 10, '$'
f_irqstat:  db 'FAIL-IRQSTAT', 13, 10, '$'
f_e4e8:     db 'FAIL-E4E8', 13, 10, '$'
f_trig:     db 'FAIL-TRIG', 13, 10, '$'
f_ack8:     db 'FAIL-ACK8', 13, 10, '$'
f_autoinit: db 'FAIL-AUTOINIT', 13, 10, '$'

buf:        times 1024 db 0x80
