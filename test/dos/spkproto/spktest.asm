; SPKTEST.COM — PC speaker probe: the OUT line, and a tone sequence a WAV
; capture can be measured against.
;
; Two halves, because the speaker has two guest-visible surfaces and only one
; of them can be asserted from inside the guest:
;
;   1. Port 61h bit 5 is PIT channel 2's OUT line. Programmed to mode 3 with
;      the slowest possible divisor it must be seen both HIGH and LOW —
;      programs poll this both as a "is there a PIT" check and as a sub-tick
;      delay source, and it is the one part of the speaker path a guest can
;      verify by itself. Prints OUT-OK / FAIL-OUT.
;
;   2. Three tones of known frequency and duration, driven with the gate
;      (61h bits 0-1) exactly as a DOS game does. Nothing in the guest can
;      hear them; they exist so a host-side capture can measure the pitch:
;
;         1000.2 Hz  divisor 1193   ~0.5 s
;          500.1 Hz  divisor 2386   ~0.5 s
;         1999.6 Hz  divisor  597   ~0.5 s
;
;      separated by ~0.2 s of silence (gate off, so the mixer's stream
;      lifecycle is exercised too, not just the oscillator).
;
; Durations come from the BIOS tick count at 0040:006C (18.2 Hz), so the
; capture's segment boundaries are the guest's own clock, not the host's.
;
; Ends holding for a key so a harness can screenshot the result.
        org 0x100
start:
        ; ---- phase 1: the OUT line at port 61h bit 5 ----
        mov al, 0xB6            ; ch2, lo/hi, mode 3 (square), binary
        out 0x43, al
        mov ax, 0xFFFF          ; slowest square: 18.2 Hz, ~27 ms per half
        out 0x42, al
        mov al, ah
        out 0x42, al
        in  al, 0x61
        or  al, 0x01            ; gate the counter, leave the driver (bit 1) off
        and al, 0xFD
        out 0x61, al

        xor bl, bl              ; bit 0 = saw HIGH, bit 1 = saw LOW
        mov cx, 0               ; 65536 samples spans several 27 ms halves
.poll:
        in  al, 0x61
        test al, 0x20
        jz  .low
        or  bl, 1
        jmp .next
.low:
        or  bl, 2
.next:
        cmp bl, 3
        je  .out_ok
        loop .poll
        mov dx, msg_fout
        call print
        jmp tones
.out_ok:
        mov dx, msg_out
        call print

        ; ---- phase 2: the tone sequence ----
tones:
        mov bx, 1193            ; 1000.2 Hz
        call tone
        call gap
        mov bx, 2386            ; 500.1 Hz
        call tone
        call gap
        mov bx, 597             ; 1999.6 Hz
        call tone
        call silence

        mov dx, msg_done
        call print
.hold:
        mov ah, 0
        int 0x16
        int 0x20

; Play the divisor in BX for 9 ticks (~0.5 s).
tone:
        mov al, 0xB6
        out 0x43, al
        mov ax, bx
        out 0x42, al
        mov al, ah
        out 0x42, al
        in  al, 0x61
        or  al, 0x03            ; gate + driver: the cone moves
        out 0x61, al
        mov cx, 9
        call wait_ticks
        ret

; Gate off for 4 ticks (~0.22 s).
gap:
        call silence
        mov cx, 4
        call wait_ticks
        ret

silence:
        in  al, 0x61
        and al, 0xFC
        out 0x61, al
        ret

; Wait CX BIOS ticks (18.2 Hz) by watching 0040:006C.
wait_ticks:
        push ds
        push ax
        push bx
        mov ax, 0x40
        mov ds, ax
        mov bx, [0x6C]
.spin:
        mov ax, [0x6C]
        cmp ax, bx
        je  .spin
        mov bx, ax
        loop .spin
        pop bx
        pop ax
        pop ds
        ret

print:
        mov ah, 9
        int 0x21
        ret

msg_out:  db 'OUT-OK', 13, 10, '$'
msg_fout: db 'FAIL-OUT', 13, 10, '$'
msg_done: db 'TONES-DONE', 13, 10, '$'
