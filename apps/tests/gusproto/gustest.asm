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
;
; Later phases (timers/IRQ, DMA upload, an audible voice) join as the
; corresponding emulation lands — same file, appended markers.
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

msg_dram: db 'GDRAM-OK', 13, 10, '$'
msg_reg:  db 'GREG-OK', 13, 10, '$'
msg_fd:   db 'FAIL-GDRAM', 13, 10, '$'
msg_fr:   db 'FAIL-GREG', 13, 10, '$'
