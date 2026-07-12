; SBTEST.COM — Sound Blaster single-cycle completion-protocol probe.
;
; Exercises the three real-chip behaviors DOS sound drivers key their
; completion logic on, each lost or missing at least once in the emulated
; card's history (see vsb.rs):
;
;   1. DSP write-status busy bit (base+0x0C bit 7) FLICKERS while a
;      single-cycle transfer is in flight — PoP's stop-digitized-sound
;      routine waits for busy, then for the busy→idle edge, before 0xD0.
;      Always-ready hangs the first wait (end-door hang); busy held for
;      the whole block stalls the routine a full sample per game frame.
;   2. The 8237 status register (port 0x08) latches the channel's TC bit
;      at terminal count — PoP 1.4's digi.drv ISR reads it to decide the
;      completion IRQ is "mine" and chains the IRQ away otherwise.
;   3. The channel current-count reads 0xFFFF (post-TC underflow) after a
;      completed single-cycle transfer, until the channel is restarted.
;
; Prints BUSY-OK, EDGE-OK, TC-OK (all three = pass) or a FAIL-* line.
; CI: test/hosted_games.sh runs this on the emulated card and asserts TC-OK.
        org 0x100
start:
        ; DSP reset: base 0x220
        mov dx, 0x226
        mov al, 1
        out dx, al
        mov cx, 100
.rstlp: loop .rstlp
        xor al, al
        out dx, al
        ; wait for 0xAA on read-data (base+0x0E status, base+0x0A data)
        mov cx, 0xFFFF
.aawait:
        mov dx, 0x22E
        in  al, dx
        test al, 0x80
        jz  .aanext
        mov dx, 0x22A
        in  al, dx
        cmp al, 0xAA
        je  .reset_ok
.aanext:
        loop .aawait
        jmp fail_busy
.reset_ok:
        mov dx, 0x22C          ; speaker on
        mov al, 0xD1
        out dx, al

        ; ---- phase 1+2: busy flicker and the busy->idle edge ----
        mov ax, 3999           ; 4000-byte block
        call startblk
        mov dx, 0x22C
        mov cx, 0xFFFF
.busywait:
        in  al, dx
        test al, 0x80
        jnz busy_seen
        loop .busywait
        jmp fail_busy
busy_seen:
        mov ah, 9
        mov dx, msg_busy
        int 0x21
        mov dx, 0x22C
        mov cx, 0xFFFF
.idlewait:
        in  al, dx
        test al, 0x80
        jz  edge_seen
        loop .idlewait
        jmp fail_edge
edge_seen:
        mov ah, 9
        mov dx, msg_edge
        int 0x21
        mov dx, 0x22C          ; stop the phase-1 transfer
        mov al, 0xD0
        out dx, al

        ; ---- phase 3: TC status bit + count underflow on completion ----
        mov ax, 255            ; short block (256 bytes, ~23 ms at 11 kHz)
        call startblk
        mov bx, 0x1000         ; bounded poll: outer x inner
.tcouter:
        mov cx, 0x0100
.tcin:  in  al, 0x08           ; DMA1 status; reading clears the TC bits
        test al, 0x02          ; ch1 TC
        jnz tc_seen
        loop .tcin
        dec bx
        jnz .tcouter
        jmp fail_tc
tc_seen:
        ; current count must now read the post-TC underflow value 0xFFFF
        xor al, al
        out 0x0C, al           ; clear byte-pointer flip-flop
        in  al, 0x03           ; count lo
        mov ah, al
        in  al, 0x03           ; count hi
        cmp ax, 0xFFFF
        jne fail_tc
        mov ah, 9
        mov dx, msg_tc
        int 0x21
        jmp exit

fail_busy:
        mov ah, 9
        mov dx, msg_fb
        int 0x21
        jmp exit
fail_edge:
        mov ah, 9
        mov dx, msg_fe
        int 0x21
        jmp exit
fail_tc:
        mov ah, 9
        mov dx, msg_ft
        int 0x21
exit:
        ; Park on a keypress so the harness's 1 Hz screen snapshot can catch
        ; the verdict (it treats an early guest exit as a failure).
        mov ah, 0
        int 0x16
        mov ax, 0x4C00
        int 0x21

; start a single-cycle 8-bit transfer of AX+1 bytes at buf on 8237 ch1 + DSP
startblk:
        push ax
        mov al, 0x05
        out 0x0A, al           ; mask ch1
        mov al, 0x49
        out 0x0B, al           ; mode: single, read (mem->card), ch1
        xor al, al
        out 0x0C, al           ; clear flip-flop
        mov ax, cs
        mov bx, ax
        shr bx, 12             ; page bits 16-19
        shl ax, 4
        add ax, buf
        adc bx, 0
        out 0x02, al           ; addr lo
        mov al, ah
        out 0x02, al           ; addr hi
        mov ax, bx
        out 0x83, al           ; page (ch1)
        pop ax                 ; count-1
        out 0x03, al
        mov al, ah
        out 0x03, al
        push ax
        mov al, 0x01
        out 0x0A, al           ; unmask ch1
        mov dx, 0x22C
        mov al, 0x40           ; time constant ~11 kHz
        out dx, al
        mov al, 0xA6
        out dx, al
        mov al, 0x14           ; single-cycle 8-bit output
        out dx, al
        pop ax
        out dx, al             ; len lo
        mov al, ah
        out dx, al             ; len hi
        ret

msg_busy: db 'BUSY-OK', 13, 10, '$'
msg_edge: db 'EDGE-OK', 13, 10, '$'
msg_tc:   db 'TC-OK', 13, 10, '$'
msg_fb:   db 'FAIL-BUSY', 13, 10, '$'
msg_fe:   db 'FAIL-EDGE', 13, 10, '$'
msg_ft:   db 'FAIL-TC', 13, 10, '$'
buf:      times 4000 db 0x80
