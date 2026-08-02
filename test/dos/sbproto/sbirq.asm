; SBIRQ.COM — Sound Blaster SUSTAINED completion-IRQ probe.
;
; Every other SB probe here polls (busy bit, 8237 TC, current count), so none
; of them notices whether the completion INTERRUPT keeps arriving. That gap hid
; a real bug: the kernel re-armed a hardcoded host IRQ 5 after the guest's EOI,
; so on a machine whose card is strapped elsewhere (86Box restraps to IRQ 7)
; the FIRST completion was delivered and every later one was masked off
; forever. Polled probes passed; Doom replayed one fragment as a tick and
; Duke Nukem 3D's IRQ detection reported "invalid or conflicting IRQ".
;
; So: arm auto-init DMA — the mode a real music driver uses, where the card
; raises one IRQ per block with no reprogramming in between — and COUNT the
; interrupts over a fixed window. One is not enough. The two failures are
; deliberately distinct markers:
;
;   FAIL-IRQ-NONE       no completion interrupt at all (wrong line, masked,
;                       never routed, relay guard rejecting it)
;   FAIL-IRQ-STALLED    the first arrived and the stream then stopped — the
;                       re-arm bug's exact signature
;   IRQ-SUSTAINED-OK    n blocks delivered, n >= MIN_IRQS
;
; The IRQ line is taken from BLASTER in the environment, not assumed: the
; whole point is that the line the guest is TOLD to use is the line that
; works, wherever the card physically sits.
;
; Writes every line to C:\SBIRQ.LOG as well as the screen, so a GUI-only
; backend (86Box, the faithful SB16 reference) can be asserted on after the
; fact — same mechanism as SBTEST.COM.
        org 0x100

MIN_IRQS    equ 4              ; blocks that must complete inside the window
WINDOW_TICKS equ 37            ; ~2 s at 18.2 Hz
BLKLEN      equ 512            ; bytes per auto-init block

start:
        mov ah, 0x3C
        xor cx, cx
        mov dx, fname
        int 0x21
        jc  .nolog
        mov [fhandle], ax
.nolog:
        call parse_blaster     ; -> [sb_irq]
        call dsp_reset
        jc  fail_reset

        ; ---- hook the vector for the declared IRQ -----------------------
        ; IRQ 0-7 -> INT 08h+n. Save the old handler so a failed run leaves
        ; the machine as it found it.
        mov al, [sb_irq]
        add al, 8
        mov [int_no], al
        mov ah, 0x35           ; get vector
        int 0x21
        mov [old_off], bx
        mov ax, es
        mov [old_seg], ax
        push ds
        mov ax, cs
        mov ds, ax
        mov dx, isr
        mov al, [int_no]
        mov ah, 0x25           ; set vector
        int 0x21
        pop ds

        ; ---- unmask the line at the PIC --------------------------------
        mov cl, [sb_irq]
        mov al, 1
        shl al, cl
        not al
        mov ah, al
        in  al, 0x21
        and al, ah
        out 0x21, al

        call start_autoinit

        ; ---- count interrupts for a fixed window -----------------------
        sti
        xor ax, ax
        mov es, ax
        mov ax, [es:0x46C]     ; BIOS tick count
        mov [t0], ax
.wait:
        mov ax, [es:0x46C]
        sub ax, [t0]
        cmp ax, WINDOW_TICKS
        jae .done
        cmp byte [irq_count], MIN_IRQS
        jb  .wait              ; stop early once satisfied
.done:
        cli
        call stop_dsp
        call restore

        ; ---- verdict ---------------------------------------------------
        mov al, [irq_count]
        or  al, al
        jz  fail_none
        cmp al, MIN_IRQS
        jb  fail_stalled
        mov dx, msg_ok
        call emit
        call emit_count
        jmp exit
fail_none:
        mov dx, msg_none
        call emit
        jmp exit
fail_stalled:
        mov dx, msg_stalled
        call emit
        call emit_count
        jmp exit
fail_reset:
        mov dx, msg_noreset
        call emit
exit:
        mov bx, [fhandle]
        cmp bx, 0xFFFF
        je  .noclose
        mov ah, 0x3E
        int 0x21
.noclose:
        mov ax, 0x4C00
        int 0x21

; ---------------------------------------------------------------------------
; The ISR: acknowledge the card, count, chain nothing, EOI.
; Reading base+0x0E is what clears an 8-bit completion on a real DSP; without
; it the card keeps the line asserted and the next block's edge never comes.
; ---------------------------------------------------------------------------
isr:
        push ax
        push dx
        mov dx, 0x22E          ; base+0x0E — 8-bit IRQ acknowledge
        in  al, dx
        inc byte [cs:irq_count]
        mov al, 0x20
        out 0x20, al           ; non-specific EOI to the master PIC
        pop dx
        pop ax
        iret

; ---------------------------------------------------------------------------
; BLASTER=A220 I7 D1 ... — take the I field. Defaults to 7 (the SB16 power-on
; strap) when unset, but a missing BLASTER is itself worth reporting.
; ---------------------------------------------------------------------------
parse_blaster:
        push es
        mov ax, [0x2C]         ; PSP environment segment
        mov es, ax
        xor si, si
.scan:
        cmp byte [es:si], 0
        je  .nofind
        ; match "BLASTER="
        push si
        mov di, blaster_key
        mov cx, 8
.cmp:
        mov al, [es:si]
        cmp al, [cs:di]
        jne .next
        inc si
        inc di
        loop .cmp
        pop si
        add si, 8
        jmp .found
.next:
        pop si
.skip:
        cmp byte [es:si], 0
        je  .adv
        inc si
        jmp .skip
.adv:
        inc si
        jmp .scan
.found:
        ; walk tokens looking for 'I'
.tok:
        mov al, [es:si]
        or  al, al
        je  .nofind
        cmp al, 'I'
        je  .got
        inc si
        jmp .tok
.got:
        inc si
        xor bx, bx
.dig:
        mov al, [es:si]
        cmp al, '0'
        jb  .store
        cmp al, '9'
        ja  .store
        sub al, '0'
        shl bx, 1
        mov cx, bx
        shl bx, 2
        add bx, cx             ; bx *= 10
        xor ah, ah
        add bx, ax
        inc si
        jmp .dig
.store:
        cmp bl, 8
        jae .nofind            ; only master-PIC lines here
        mov [sb_irq], bl
.nofind:
        pop es
        ret

; ---------------------------------------------------------------------------
dsp_reset:
        mov dx, 0x226
        mov al, 1
        out dx, al
        mov cx, 100
.rst:   loop .rst
        xor al, al
        out dx, al
        mov cx, 0xFFFF
.await:
        mov dx, 0x22E
        in  al, dx
        test al, 0x80
        jz  .nextw
        mov dx, 0x22A
        in  al, dx
        cmp al, 0xAA
        je  .ok
.nextw: loop .await
        stc
        ret
.ok:
        mov dx, 0x22C
        mov al, 0xD1           ; speaker on
        out dx, al
        clc
        ret

; ---------------------------------------------------------------------------
; Auto-init 8-bit output: the 8237 in auto-init single mode reloads its own
; address/count at terminal count, and DSP 0x1C keeps the card running, so the
; card raises one completion IRQ per block with NO further programming. That
; is exactly what a music driver does, and exactly what a one-shot re-arm bug
; breaks after the first block.
; ---------------------------------------------------------------------------
start_autoinit:
        mov al, 0x05
        out 0x0A, al           ; mask ch1
        xor al, al
        out 0x0C, al           ; clear flip-flop
        mov al, 0x59           ; single, auto-init, read (mem->card), ch1
        out 0x0B, al
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
        out 0x83, al           ; page (ch1)
        mov ax, BLKLEN - 1
        out 0x03, al
        mov al, ah
        out 0x03, al
        mov al, 0x01
        out 0x0A, al           ; unmask ch1

        mov dx, 0x22C
        mov al, 0x40           ; time constant
        out dx, al
        mov al, 0xA6           ; ~11 kHz -> ~46 ms per 512-byte block
        out dx, al
        mov al, 0x48           ; set DMA block size
        out dx, al
        mov ax, BLKLEN - 1
        out dx, al
        mov al, ah
        out dx, al
        mov al, 0x1C           ; auto-init 8-bit output
        out dx, al
        ret

stop_dsp:
        mov dx, 0x22C
        mov al, 0xDA           ; exit auto-init 8-bit
        out dx, al
        mov al, 0xD0           ; halt DMA
        out dx, al
        mov al, 0x05
        out 0x0A, al           ; mask ch1
        ret

restore:
        push ds
        mov dx, [old_off]
        mov ax, [old_seg]
        mov ds, ax
        mov al, [cs:int_no]
        mov ah, 0x25
        int 0x21
        pop ds
        ret

; ---------------------------------------------------------------------------
emit_count:
        mov al, [irq_count]
        xor ah, ah
        mov bl, 10
        div bl                 ; al = tens, ah = units
        add al, '0'
        mov [cnt_t], al
        mov al, ah
        add al, '0'
        mov [cnt_u], al
        mov dx, msg_count
        call emit
        ret

; print DS:DX ('$'-terminated) and append it to the log
emit:
        push ax
        push bx
        push cx
        push dx
        push si
        mov ah, 0x09
        int 0x21
        mov bx, [fhandle]
        cmp bx, 0xFFFF
        je  .done
        mov si, dx
        xor cx, cx
.len:
        cmp byte [si], '$'
        je  .write
        inc si
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

blaster_key: db 'BLASTER='
fname:       db 'C:\SBIRQ.LOG', 0
fhandle:     dw 0xFFFF
sb_irq:      db 7
int_no:      db 0
old_off:     dw 0
old_seg:     dw 0
t0:          dw 0
irq_count:   db 0
msg_ok:      db 'IRQ-SUSTAINED-OK', 13, 10, '$'
msg_none:    db 'FAIL-IRQ-NONE', 13, 10, '$'
msg_stalled: db 'FAIL-IRQ-STALLED', 13, 10, '$'
msg_noreset: db 'FAIL-DSP-RESET', 13, 10, '$'
msg_count:   db 'IRQ-COUNT='
cnt_t:       db '0'
cnt_u:       db '0', 13, 10, '$'
buf:         times BLKLEN db 0x80
