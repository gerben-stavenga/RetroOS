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
; Prints BUSY-OK, EDGE-OK, TC-OK (all three = pass) or a FAIL-* line, AND
; appends every line to C:\SBTEST.LOG. The file is what makes this probe
; usable on a backend with no log to grep: 86Box is a GUI application whose
; SB16 model is the faithful one, so the physical-configuration sweep runs
; there and the harness reads the verdict out of the disk image afterwards
; instead of scraping a screen.
; CI: test/hosted_games.sh runs this on the emulated card and asserts TC-OK.
        org 0x100
start:
        ; C:\SBTEST.LOG — the verdict a backend without a debug log can be
        ; asked for after the fact. A failure to create it is not fatal:
        ; the screen/log path still works (handle stays 0xFFFF).
        mov ah, 0x3C
        xor cx, cx
        mov dx, fname
        int 0x21
        jc  .nolog
        mov [fhandle], ax
.nolog:
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
        mov dx, msg_busy
        call emit
        mov dx, 0x22C
        mov cx, 0xFFFF
.idlewait:
        in  al, dx
        test al, 0x80
        jz  edge_seen
        loop .idlewait
        jmp fail_edge
edge_seen:
        mov dx, msg_edge
        call emit
        mov dx, 0x22C          ; stop the phase-1 transfer
        mov al, 0xD0
        out dx, al

        ; ---- phase 3: TC status bit + count underflow on completion ----
        ; Phase 2 left the DSP PAUSED (it sent 0xD0 to stop that transfer), and
        ; a real SB16 keeps honouring that pause across the next start command:
        ; the 0x14 below arms the 8237, one already-in-flight byte moves, and
        ; the card then stops asking. Observed on 86Box as cnt=00FE against a
        ; programmed 0x00FF, with the TC bit never latching. Resume first.
        ; (QEMU's sb16 does not model the pause holding across a new start,
        ; which is why this only ever failed on the faithful card.)
        mov dx, 0x22C
        mov al, 0xD4           ; continue 8-bit DMA
        out dx, al
        mov ax, 255            ; short block (256 bytes, ~23 ms at 11 kHz)
        call startblk
        ; Bound the poll in TIME, not iterations. Port 0x08 is trapped by the
        ; kernel (the 8237 windows are never granted to a guest, because the
        ; addresses it programs are COW-relocated), so every read here is a VM
        ; exit. The old 0x1000 x 0x100 iteration bound is ~1M exits: on a slow
        ; backend that outlives any sane test timeout, so a card that never
        ; raises TC was indistinguishable from a probe still running. Five BIOS
        ; ticks is ~275 ms — an order of magnitude past the 23 ms the block
        ; needs — and reports FAIL-TC while anyone is still watching.
        push es
        xor ax, ax
        mov es, ax
        mov ax, [es:0x46C]
        mov bx, ax             ; t0
.tcin:  in  al, 0x08           ; DMA1 status; reading clears the TC bits
        test al, 0x02          ; ch1 TC
        jnz .tc_hit
        mov ax, [es:0x46C]
        sub ax, bx
        cmp ax, 5
        jb  .tcin
        pop es
        ; The status bit never latched. Report the controller's CURRENT COUNT
        ; with it: that says whether the real 8237 ran this block at all.
        ;   ~0x00FF (what was programmed) -> it never started
        ;   something in between          -> it is counting, TC just not seen
        ;   0xFFFF                        -> it finished and the TC bit was lost
        call read_count
        mov [cnt_val], ax
        mov dx, msg_ftbit
        call emit
        call emit_count
        jmp exit
.tc_hit:
        pop es
        ; current count must now read the post-TC underflow value 0xFFFF
        call read_count
        cmp ax, 0xFFFF
        je  .tc_ok
        mov [cnt_val], ax
        mov dx, msg_ftcnt
        call emit
        call emit_count
        jmp exit
.tc_ok:
        mov dx, msg_tc
        call emit
        jmp exit

; ---------------------------------------------------------------------------
; DMA1 ch1 current count, low byte then high, via the byte-pointer flip-flop.
; Served by the kernel from the REAL controller in passthrough, so this is the
; physical chip's progress, not a shadow.
read_count:
        xor al, al
        out 0x0C, al           ; clear byte-pointer flip-flop
        in  al, 0x03           ; count lo
        mov ah, al
        in  al, 0x03           ; count hi
        xchg al, ah            ; -> ax = hi:lo
        ret

; print 'cnt=XXXX' for [cnt_val]
emit_count:
        mov ax, [cnt_val]
        mov di, cnt_hex
        mov cx, 4
.nib:   rol ax, 4
        push ax
        and al, 0x0F
        add al, '0'
        cmp al, '9'
        jbe .put
        add al, 7
.put:   mov [di], al
        inc di
        pop ax
        loop .nib
        mov dx, msg_cnt
        call emit
        ret

fail_busy:
        mov dx, msg_fb
        call emit
        jmp exit
fail_edge:
        mov dx, msg_fe
        call emit
        jmp exit
exit:
        mov bx, [fhandle]
        cmp bx, 0xFFFF
        je  .noclose
        mov ah, 0x3E
        int 0x21
.noclose:
        ; Park on a keypress so the harness's 1 Hz screen snapshot can catch
        ; the verdict (it treats an early guest exit as a failure).
        mov ah, 0
        int 0x16
        mov ax, 0x4C00
        int 0x21

; Print DS:DX ('$'-terminated) and append the same bytes to the log file.
emit:
        push ax
        push bx
        push cx
        push dx
        push si
        mov ah, 9
        int 0x21               ; screen
        mov bx, [fhandle]
        cmp bx, 0xFFFF
        je  .done
        mov si, dx             ; measure up to the '$'
        xor cx, cx
.len:
        lodsb
        cmp al, '$'
        je  .write
        inc cx
        jmp .len
.write:
        mov ah, 0x40           ; write CX bytes at DS:DX to BX
        int 0x21
.done:
        pop si
        pop dx
        pop cx
        pop bx
        pop ax
        ret

; start a single-cycle 8-bit transfer of AX+1 bytes at buf on 8237 ch1 + DSP
startblk:
        mov [blk_len], ax      ; count-1, kept somewhere the addr writes
                               ; cannot clobber (see below)
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
        mov ax, [blk_len]
        out 0x03, al           ; 8237 count lo
        mov al, ah
        out 0x03, al           ; 8237 count hi
        mov al, 0x01
        out 0x0A, al           ; unmask ch1
        mov dx, 0x22C
        mov al, 0x40           ; time constant ~11 kHz
        out dx, al
        mov al, 0xA6
        out dx, al
        mov al, 0x14           ; single-cycle 8-bit output
        out dx, al
        ; The DSP gets its OWN length, and it must be the real one. This used
        ; to come from a `push ax` issued AFTER `mov al, ah` had already
        ; overwritten al — so the saved value was 0x0000 and the card was told
        ; "transfer 1 byte" while the 8237 was correctly set to 256. The chip
        ; then moved exactly one byte per start command and never reached
        ; terminal count: FAIL-TC-NOBIT with cnt walking 00FF -> 00FE -> 00FD.
        ; Only a real SB16 shows it; our emulated card takes the block length
        ; from the 8237 count instead of the DSP command, so it played the
        ; whole buffer and passed.
        mov ax, [blk_len]
        out dx, al             ; len lo
        mov al, ah
        out dx, al             ; len hi
        ret

blk_len: dw 0

fname:    db 'C:\SBTEST.LOG', 0
fhandle:  dw 0xFFFF
msg_busy: db 'BUSY-OK', 13, 10, '$'
msg_edge: db 'EDGE-OK', 13, 10, '$'
msg_tc:   db 'TC-OK', 13, 10, '$'
msg_fb:   db 'FAIL-BUSY', 13, 10, '$'
msg_fe:   db 'FAIL-EDGE', 13, 10, '$'
msg_ftbit: db 'FAIL-TC-NOBIT', 13, 10, '$'
msg_ftcnt: db 'FAIL-TC-COUNT', 13, 10, '$'
msg_cnt:  db 'cnt='
cnt_hex:  db '0000', 13, 10, '$'
cnt_val:  dw 0
buf:      times 4000 db 0x80
