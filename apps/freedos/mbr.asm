; Minimal MBR: load active partition's VBR and jump to it.
; Assembled with: nasm -o mbr.bin mbr.asm

[BITS 16]
[ORG 0x7C00]

start:
    cli
    xor ax, ax
    mov ss, ax
    mov sp, 0x7C00
    mov ds, ax
    mov es, ax
    sti

    ; Relocate MBR to 0x0600 so VBR can load at 0x7C00
    mov si, 0x7C00
    mov di, 0x0600
    mov cx, 256
    rep movsw
    jmp 0x0000:relocated
relocated equ 0x0600 + (post_reloc - start)

post_reloc:
    ; Scan partition table for active entry (0x80)
    mov si, 0x0600 + 446      ; partition table in relocated MBR
    mov cx, 4
.scan:
    cmp byte [si], 0x80
    je .found
    add si, 16
    loop .scan
    jmp .hang

.found:
    ; SI points to active partition entry
    ; Use LBA read (INT 13h AH=42h)
    mov dl, 0x80              ; first hard disk

    ; Build DAP on stack
    push dword 0              ; high 32 bits of LBA
    push dword [si+8]         ; low 32 bits of LBA (partition start)
    push word 0x0000          ; segment
    push word 0x7C00          ; offset
    push word 1               ; sector count
    push word 0x0010          ; packet size + reserved
    mov ah, 0x42
    mov si, sp
    int 0x13
    jc .hang

    add sp, 16
    jmp 0x0000:0x7C00

.hang:
    hlt
    jmp .hang

    ; Pad to partition table
    times 446-($-$$) db 0
    ; Partition table and signature filled by make_freedos_image.sh
    times 510-($-$$) db 0
    dw 0xAA55
