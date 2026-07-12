; GUSTEST.COM — Gravis UltraSound (GF1) emulation probe.
;
; Exercises the emulated GUS at ULTRASND=240,1,1,5,5 the way real drivers
; do, one phase per marker (a FAIL-* line stops the run):
;
;   GDRAM-OK  — chip reset, then the standard detection poke/peek: distinct
;               bytes at DRAM 0x00000 and 0xFFFFF both read back (full 1 MB
;               board, no aliasing inside the 20-bit window).
;   GREG-OK   — GF1 register-file write/readback through the voice-select /
;               register-select / data-low/high scheme: a 16-bit voice
;               register (frequency control) and the global active-voices
;               register (readback sets the top two bits).
;   GTIMER-OK — timer 1 (80 µs units) programmed through the AdLib-shaped
;               2X8/2X9 window + reg 0x45 IRQ enable + reset-reg master
;               enable actually raises the ULTRASND IRQ (5 -> INT 0Dh),
;               and the ISR sees the T1 bit in the 2X6 IRQ status.
;   GDMA-OK   — a 256-byte sample upload through the virtual 8237 (ch 1) +
;               GF1 regs 0x42/0x41 lands in DRAM byte-exact, raises the
;               TC IRQ, and reading 0x41 (bit6 set) acks it.
;   GVOICE-OK — the uploaded data programmed as a looping voice actually
;               plays: the live current-address register moves.
; CI: test/hosted_games.sh runs this and asserts every marker.
        org 0x100

GF1_VOICE  equ 0x342           ; voice select (page)
GF1_REG    equ 0x343           ; register select
GF1_DATLO  equ 0x344           ; data low byte (16-bit registers)
GF1_DATHI  equ 0x345           ; data high byte / 8-bit register data
GF1_DRAM   equ 0x347           ; DRAM peek/poke at global regs 0x43/0x44

start:
        ; ---- chip reset: reg 0x4C bit0 low, settle, then high ----
        mov al, 0x4C
        call selreg
        xor al, al
        call wr8
        mov cx, 100
.rst:   loop .rst
        mov al, 0x4C
        call selreg
        mov al, 1
        call wr8

        ; ---- phase 1: DRAM poke/peek at both ends of the 1 MB window ----
        xor ax, ax             ; addr 0x00000 <- 0x55
        xor bl, bl
        call set_dram_addr
        mov dx, GF1_DRAM
        mov al, 0x55
        out dx, al
        mov ax, 0xFFFF         ; addr 0xFFFFF <- 0xAA
        mov bl, 0x0F
        call set_dram_addr
        mov dx, GF1_DRAM
        mov al, 0xAA
        out dx, al
        mov ax, 0xFFFF         ; top byte reads back?
        mov bl, 0x0F
        call set_dram_addr
        mov dx, GF1_DRAM
        in  al, dx
        cmp al, 0xAA
        jne fail_dram
        xor ax, ax             ; byte 0 unmolested (no alias)?
        xor bl, bl
        call set_dram_addr
        mov dx, GF1_DRAM
        in  al, dx
        cmp al, 0x55
        jne fail_dram
        mov ah, 9
        mov dx, msg_dram
        int 0x21

        ; ---- phase 2: register write/readback ----
        mov dx, GF1_VOICE      ; voice 3
        mov al, 3
        out dx, al
        mov al, 0x01           ; frequency control (16-bit voice register)
        call selreg
        mov ax, 0x2345
        call wr16
        mov al, 0x81           ; read alias
        call selreg
        call rd16
        cmp bx, 0x2345
        jne fail_reg
        mov al, 0x0E           ; active voices = 32 (raw 0x1F)
        call selreg
        mov al, 0x1F
        call wr8
        mov al, 0x8E
        call selreg
        call rd8
        cmp al, 0xDF           ; hardware sets the top two bits on readback
        jne fail_reg
        mov ah, 9
        mov dx, msg_reg
        int 0x21

        ; ---- phase 3: timer 1 -> ULTRASND IRQ 5 (INT 0Dh) ----
        xor ax, ax
        mov es, ax
        cli
        mov word [es:0x0D*4], irq5_isr
        mov [es:0x0D*4+2], cs
        in  al, 0x21           ; unmask IRQ 5 on the master PIC
        and al, 0xDF
        out 0x21, al
        sti
        mov al, 0x4C           ; reset reg: run + DAC + master IRQ enable
        call selreg
        mov al, 7
        call wr8
        mov al, 0x46           ; T1 count 156: (256-156)*80us = 8 ms period
        call selreg
        mov al, 156
        call wr8
        mov al, 0x45           ; enable the T1 IRQ
        call selreg
        mov al, 0x04
        call wr8
        mov dx, 0x248          ; AdLib window: index 4 = timer control
        mov al, 0x04
        out dx, al
        inc dx
        mov al, 0x01           ; start T1
        out dx, al
        mov bx, irqflag        ; wait ~2s of real time for the ISR flag —
        call wait_flag         ; instruction-count loops expire in ms on KVM
        jc  fail_timer
timer_seen:
        mov ah, 9
        mov dx, msg_timer
        int 0x21

        ; ---- phase 4: DMA sample upload + TC IRQ ----
        mov bx, 0              ; fill pattern: buf[i] = i ^ 0x5A
.fill:  mov al, bl
        xor al, 0x5A
        mov [dmabuf+bx], al
        inc bx
        cmp bx, 256
        jne .fill
        mov al, 0x05           ; program virtual 8237 ch1: mask
        out 0x0A, al
        mov al, 0x49           ; mode: single, read (mem -> card), ch1
        out 0x0B, al
        xor al, al
        out 0x0C, al           ; clear flip-flop
        mov ax, cs
        mov bx, ax
        shr bx, 12             ; page bits 19:16
        shl ax, 4
        add ax, dmabuf
        adc bx, 0
        out 0x02, al           ; addr lo
        mov al, ah
        out 0x02, al           ; addr hi
        mov ax, bx
        out 0x83, al           ; page (ch1)
        mov ax, 255            ; count - 1
        out 0x03, al
        mov al, ah
        out 0x03, al
        mov al, 0x01
        out 0x0A, al           ; unmask ch1
        mov al, 0x42           ; GF1 DMA start address: DRAM 0 (units of 16)
        call selreg
        xor ax, ax
        call wr16
        mov al, 0x41           ; enable upload + TC IRQ (bits 0,5)
        call selreg
        mov al, 0x21
        call wr8
        mov bx, dmaflag        ; wait ~2s of real time for the TC IRQ
        call wait_flag
        jc  fail_dma
dma_seen:
        xor ax, ax             ; DRAM[0] == 0x00 ^ 0x5A?
        xor bl, bl
        call set_dram_addr
        mov dx, GF1_DRAM
        in  al, dx
        cmp al, 0x5A
        jne fail_dma
        mov ax, 255            ; DRAM[255] == 255 ^ 0x5A = 0xA5?
        xor bl, bl
        call set_dram_addr
        mov dx, GF1_DRAM
        in  al, dx
        cmp al, 0xA5
        jne fail_dma
        mov ah, 9
        mov dx, msg_dma
        int 0x21

        ; ---- phase 5: the uploaded block as a looping, audible voice ----
        mov dx, GF1_VOICE      ; voice 0
        xor al, al
        out dx, al
        mov al, 0x01           ; frequency control: 1.0 frames/sample
        call selreg
        mov ax, 0x0400
        call wr16
        mov al, 0x02           ; start = 0
        call selreg
        xor ax, ax
        call wr16
        mov al, 0x03
        call selreg
        xor ax, ax
        call wr16
        mov al, 0x04           ; end = frame 256 (combined = 256 << 9)
        call selreg
        mov ax, 0x0002
        call wr16
        mov al, 0x05
        call selreg
        xor ax, ax
        call wr16
        mov al, 0x0A           ; current address = 0
        call selreg
        xor ax, ax
        call wr16
        mov al, 0x0B
        call selreg
        xor ax, ax
        call wr16
        mov al, 0x09           ; current volume: near unity
        call selreg
        mov ax, 0xFFF0
        call wr16
        mov al, 0x0C           ; pan center
        call selreg
        mov al, 7
        call wr8
        mov al, 0x00           ; voice control: 8-bit forward loop, start
        call selreg
        mov al, 0x08
        call wr8
        mov al, 0x8B           ; watch the live current-address low register
        call selreg
        call rd16
        mov si, bx
        push es                ; wait ~2s of real time for address motion
        xor ax, ax
        mov es, ax
        mov di, [es:0x46C]     ; BIOS tick count (18.2 Hz)
.vwait: mov al, 0x8B
        call selreg
        call rd16
        cmp bx, si
        jne .vmoved
        mov ax, [es:0x46C]
        sub ax, di
        cmp ax, 36
        jb  .vwait
        pop es
        jmp fail_voice
.vmoved:
        pop es
voice_ok:
        mov ah, 9
        mov dx, msg_voice
        int 0x21
        jmp exit

irq5_isr:
        push ax
        push dx
        mov dx, 0x246          ; GF1 IRQ status
        in  al, dx
        test al, 0x04          ; timer 1?
        jz  .chk_dma
        mov byte [cs:irqflag], 1
        mov dx, 0x248          ; timer control:
        mov al, 0x04
        out dx, al
        inc dx
        mov al, 0x80           ;   clear the expiry flags...
        out dx, al
        xor al, al             ;   ...and stop both timers
        out dx, al
        jmp .eoi
.chk_dma:
        test al, 0x80          ; DMA terminal count?
        jz  .eoi
        mov al, 0x41           ; reading 0x41 acks the TC
        call selreg
        call rd8
        mov byte [cs:dmaflag], 1
.eoi:   mov al, 0x20
        out 0x20, al
        pop dx
        pop ax
        iret
irqflag: db 0
dmaflag: db 0

fail_timer:
        mov ah, 9
        mov dx, msg_ftm
        int 0x21
        jmp exit
fail_dma:
        mov ah, 9
        mov dx, msg_fdm
        int 0x21
        jmp exit
fail_voice:
        mov ah, 9
        mov dx, msg_fv
        int 0x21
        jmp exit
fail_dram:
        mov ah, 9
        mov dx, msg_fd
        int 0x21
        jmp exit
fail_reg:
        mov ah, 9
        mov dx, msg_fr
        int 0x21
exit:
        ; Park on a keypress so the harness's 1 Hz screen snapshot can catch
        ; the verdict (it treats an early guest exit as a failure).
        mov ah, 0
        int 0x16
        mov ax, 0x4C00
        int 0x21

; wait for the flag byte at [BX] (CS=DS) to go nonzero, up to ~2 s of real
; time via the BIOS tick counter (18.2 Hz). CF set on timeout. Real-time,
; not instruction-count: KVM runs the guest at native speed, where a counted
; loop expires in milliseconds — before any IRQ could possibly arrive.
wait_flag:
        push es
        push dx
        xor ax, ax
        mov es, ax
        mov dx, [es:0x46C]
.wf:    cmp byte [bx], 0
        jne .ok
        mov ax, [es:0x46C]
        sub ax, dx
        cmp ax, 36
        jb  .wf
        pop dx
        pop es
        stc
        ret
.ok:    pop dx
        pop es
        clc
        ret

; ---- GF1 register access helpers ----
; select global/voice register AL
selreg:
        mov dx, GF1_REG
        out dx, al
        ret
; write AL to the selected 8-bit register (data-high port)
wr8:
        mov dx, GF1_DATHI
        out dx, al
        ret
; write AX to the selected 16-bit register, low byte then high
wr16:
        mov dx, GF1_DATLO
        out dx, al
        mov al, ah
        inc dx
        out dx, al
        ret
; read the selected 8-bit register into AL
rd8:
        mov dx, GF1_DATHI
        in  al, dx
        ret
; read the selected 16-bit register into BX
rd16:
        mov dx, GF1_DATLO
        in  al, dx
        mov bl, al
        inc dx
        in  al, dx
        mov bh, al
        ret
; set the DRAM I/O address: AX = bits 15:0 (reg 0x43), BL = bits 19:16 (0x44)
set_dram_addr:
        push ax
        mov al, 0x43
        call selreg
        pop ax
        call wr16
        mov al, 0x44
        call selreg
        mov al, bl
        call wr8
        ret

msg_dram:  db 'GDRAM-OK', 13, 10, '$'
msg_reg:   db 'GREG-OK', 13, 10, '$'
msg_timer: db 'GTIMER-OK', 13, 10, '$'
msg_dma:   db 'GDMA-OK', 13, 10, '$'
msg_voice: db 'GVOICE-OK', 13, 10, '$'
msg_fd:    db 'FAIL-GDRAM', 13, 10, '$'
msg_fr:    db 'FAIL-GREG', 13, 10, '$'
msg_ftm:   db 'FAIL-GTIMER', 13, 10, '$'
msg_fdm:   db 'FAIL-GDMA', 13, 10, '$'
msg_fv:    db 'FAIL-GVOICE', 13, 10, '$'
dmabuf:    times 256 db 0
