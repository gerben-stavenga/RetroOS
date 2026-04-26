; TREXEC.COM — tiny TSR that logs every INT 21h call to QEMU debugcon (0xE9).
; Output format: "[INT21] AX=xxxx\n"
; Assemble: nasm -f bin -o TREXEC.COM trexec.asm

bits 16
org 0x100

    jmp install

; ─── Resident ───────────────────────────────────────────────────────────

old_int21   dd 0
r_ax        dw 0

msg_pfx     db '[INT21] AX=', 0
msg_nl      db 0x0A, 0

; INT 21 hook — log AX, then chain.
new_int21:
    mov  [cs:r_ax], ax

    pusha
    push ds
    push es

    push cs
    pop  ds

    mov  si, msg_pfx
    call bios_puts
    mov  ax, [r_ax]
    call bios_puthex4
    mov  si, msg_nl
    call bios_puts

    pop  es
    pop  ds
    popa
    jmp  far [cs:old_int21]

; ─── BIOS helpers ───────────────────────────────────────────────────────
; All output goes to QEMU debugcon port 0xE9 (use `-debugcon file:/tmp/trace.log`).

; Print ASCIIZ at DS:SI
bios_puts:
    pusha
    mov  dx, 0xE9
.loop:
    lodsb
    test al, al
    jz   .done
    out  dx, al
    jmp  .loop
.done:
    popa
    ret

; Print AL as 2 hex digits
bios_puthex2:
    push ax
    push ax
    shr  al, 4
    call hex_nibble
    pop  ax
    and  al, 0x0F
    call hex_nibble
    pop  ax
    ret

; Print AX as 4 hex digits
bios_puthex4:
    push ax
    mov  al, ah
    call bios_puthex2
    pop  ax
    call bios_puthex2
    ret

; AL = 0..F → print '0'..'f' (lowercase, matches cws/kernel format)
hex_nibble:
    cmp  al, 10
    jb   .dig
    add  al, 'a' - 10 - '0'
.dig:
    add  al, '0'
    push dx
    mov  dx, 0xE9
    out  dx, al
    pop  dx
    ret

resident_end:

; ─── Installer (discarded after going TSR) ──────────────────────────────

install:
    mov  ax, 0x3521
    int  0x21
    mov  [old_int21],   bx
    mov  [old_int21+2], es

    mov  ax, 0x2521
    mov  dx, new_int21
    int  0x21

    mov  ah, 0x09
    mov  dx, installed_msg
    int  0x21

    mov  dx, resident_end + 15
    shr  dx, 4
    mov  ax, 0x3100
    int  0x21

installed_msg db 'TREXEC: INT 21 hooked (all calls)', 0x0D, 0x0A, '$'
