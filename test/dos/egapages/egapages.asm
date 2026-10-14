; EGA graphics page selection and hidden-page redraw regression.
; Page 0 starts green, page 1 blue. Select page 1 through the BIOS, then
; overwrite page 0 red: the visible picture must remain blue.
org 0x100
    mov ax, 0x000d
    int 0x10
    mov ax, 0xa000
    mov es, ax
    ; A masked sprite byte: a VRAM read, register ALU, RAM mask/data
    ; reads, a VRAM write and a conditional branch. The fault decoder
    ; must preserve the byte and flags.
    xor di, di
    mov bl, 0x0f
    mov byte [es:di], 0x55
    mov al, [es:di]
    and al, bl
    or al, [pixel_bits]
    mov [es:di], al
    cmp al, [expected]
    jne .bad_blit
    mov al, [es:di]
    mov [result], al
    cmp byte [result], 0xa5
    jne .bad_blit
    mov dx, 0x3ce
    mov ax, 0x0f01       ; enable set/reset on all planes
    out dx, ax
    mov ax, 0x0200       ; green
    out dx, ax
    xor di, di
    mov cx, 0x1000
    xor ax, ax
    rep stosw
    mov ax, 0x0100       ; blue
    out dx, ax
    mov di, 0x2000
    mov cx, 0x1000
    xor ax, ax
    rep stosw
    mov ax, 0x0501
    int 0x10
    push ds
    mov ax, 0x40
    mov ds, ax
    cmp word [0x4c], 0x2000
    jne .bad_bda
    cmp word [0x4e], 0x2000
    jne .bad_bda
    cmp byte [0x62], 1
    jne .bad_bda
    pop ds
    mov dx, 0x3ce
    mov ax, 0x0400       ; redraw hidden page 0 red
    out dx, ax
    xor di, di
    mov cx, 0x1000
    xor ax, ax
    rep stosw
    mov dx, pass
    jmp .print
.bad_bda:
    pop ds
.bad_blit:
    mov dx, fail
.print:
    mov ah, 9
    int 0x21
.hang:
    jmp .hang
pass db 'EGA-PAGES-PASS',13,10,'$'
fail db 'EGA-PAGES-FAIL',13,10,'$'
pixel_bits db 0xa0
expected db 0xa5
result db 0
