; EGA graphics page selection and hidden-page redraw regression.
; Page 0 starts green, page 1 blue. Select page 1 through the BIOS, then
; overwrite page 0 red: the visible picture must remain blue.
org 0x100
    mov ax, 0x000d
    int 0x10
    mov ax, 0xa000
    mov es, ax
    ; Warm an entry, then patch its source register at the same CS:IP.
    mov di, 0x9000
    mov al, 0x11
    mov dl, 0x22
    call cached_store
    call cached_store
    cmp byte [es:di], 0x11
    jne .bad_blit
    mov byte [cached_store+2], 0x15 ; AL -> DL
    call cached_store
    cmp byte [es:di], 0x22
    jne .bad_blit
    ; The same IP in another VM86 CS must fetch that segment's bytes.
    push es
    push cs
    pop es
    mov bx, 512
    mov ah, 0x4a
    int 0x21
    pop es
    jc .bad_blit
    mov bx, 128
    mov ah, 0x48
    int 0x21
    jc .bad_blit
    mov [other_allocation], ax
    mov bx, cs
    sub bx, ax
    and bx, 63               ; force the same allow-list hash as the old CS
    add ax, bx
    mov [other_cs+2], ax
    push es
    mov es, ax
    mov si, cached_store
    mov di, cached_store
    mov cx, 8
    rep movsb
    mov byte [es:cached_store+2], 0x0d ; CL
    mov byte [es:cached_store+3], 0xcb ; RETF
    pop es
    mov di, 0x9000
    mov cl, 0x33
    call far [other_cs]
    cmp byte [es:di], 0x33
    jne .bad_blit
    push es
    mov es, [other_allocation]
    mov ah, 0x49
    int 0x21
    pop es
    jc .bad_blit
    ; More than one full queue, then a read barrier. Measure only stores
    ; and their final drain, excluding boot, modesetting and printing.
    rdtsc
    mov [start_low], eax
    mov [start_high], edx
    xor di, di
    mov cx, 0x8000
.stores:
    mov [es:di], cl
    inc di
    loop .stores
    mov al, [es:di-1]
    cmp al, 1
    jne .bad_blit
    rdtsc
    sub eax, [start_low]
    sbb edx, [start_high]
    mov [cycles], eax
    mov [cycles+4], edx
    ; Check every queued byte, including the stores handled on full queues.
    xor di, di
    mov cx, 0x8000
.verify:
    cmp [es:di], cl
    jne .bad_blit
    inc di
    loop .verify
    add di, 3            ; keep mixed stores away from page-edge fallback
    mov cx, 2
.mixed:
    mov byte [es:di], 0x12
    mov ah, 0x34
    mov [es:di+1], ah
    mov word [es:di+2], 0x5678
    mov eax, 0xabcdef09
    mov [es:di+4], eax
    loop .mixed         ; second execution uses the cached instructions
    cmp dword [es:di], 0x56783412
    jne .bad_blit
    cmp dword [es:di+4], 0xabcdef09
    jne .bad_blit
    mov dx, timing
    mov ah, 9
    int 0x21
    mov eax, [cycles+4]
    call print_hex
    mov eax, [cycles]
    call print_hex
    mov dx, newline
    mov ah, 9
    int 0x21
    ; A register change must apply after the preceding queued write.
    mov byte [es:di], 0x5a
    mov dx, 0x3ce
    mov ax, 0x0008       ; disable all bit-mask writes
    out dx, ax
    cmp byte [es:di], 0x5a
    jne .bad_blit
    mov ax, 0xff08
    out dx, ax
    ; Word/dword stores crossing a page stay on the ordinary decoder.
    mov word [es:0x0fff], 0x1234
    cmp word [es:0x0fff], 0x1234
    jne .bad_blit
    mov dword [es:0x1ffe], 0xabcdef09
    cmp dword [es:0x1ffe], 0xabcdef09
    jne .bad_blit
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
cached_store:
    db 0x26, 0x88, 0x05       ; MOV [ES:DI], AL (patched above)
    ret
    times 4 db 0x90
other_cs dw cached_store, 0
other_allocation dw 0
pass db 'EGA-PAGES-PASS',13,10,'$'
fail db 'EGA-PAGES-FAIL',13,10,'$'
pixel_bits db 0xa0
expected db 0xa5
result db 0
start_low dd 0
start_high dd 0
cycles dq 0
timing db 'EGA-MOV-CYCLES=','$'
newline db 13,10,'$'

print_hex:
    mov cx, 8
.digit:
    rol eax, 4
    push eax
    mov dl, al
    and dl, 15
    add dl, '0'
    cmp dl, '9'
    jbe .emit
    add dl, 'A'-'9'-1
.emit:
    mov ah, 2
    int 0x21
    pop eax
    loop .digit
    ret
