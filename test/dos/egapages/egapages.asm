; EGA graphics page selection and hidden-page redraw regression.
; Page 0 starts green, page 1 blue. Select page 1 through the BIOS, then
; overwrite page 0 red: the visible picture must remain blue.
org 0x100
    mov [rm_segment], cs
    mov ax, 0x000d
    int 0x10
    mov ax, 0xa000
    mov es, ax
    ; Execute a store, then patch its source register at the same CS:IP.
    mov di, 0x9000
    mov al, 0x11
    mov dl, 0x22
    call patched_store
    call patched_store
    cmp byte [es:di], 0x11
    jne .bad_blit
    mov byte [patched_store+2], 0x15 ; AL -> DL
    call patched_store
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
    and bx, 63               ; alias the low selector bits used by the former cache
    add ax, bx
    mov [other_cs+2], ax
    push es
    mov es, ax
    mov si, patched_store
    mov di, patched_store
    mov cx, 8
    rep movsb
    mov byte [es:patched_store+2], 0x0d ; CL
    mov byte [es:patched_store+3], 0xcb ; RETF
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
    ; Measure looped stores, excluding boot, modesetting and printing.
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
    ; Check every stored byte.
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
    loop .mixed         ; repeat at the same instruction addresses
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
    ; Unrolled scaler-like writes: 256 distinct store sites, each separated
    ; by 16 bytes. These deliberately collide in the former 64-slot cache.
    rdtsc
    mov [start_low], eax
    mov [start_high], edx
    xor di, di
    mov cx, 128
.unrolled:
%assign pixel 0
%rep 256
    mov byte [es:di+pixel], pixel & 255
    times 16-($-$$) % 16 db 0x90
%assign pixel pixel+1
%endrep
    add di, 256
    dec cx
    jz .unrolled_done
    jmp .unrolled
.unrolled_done:
    rdtsc
    sub eax, [start_low]
    sbb edx, [start_high]
    mov [cycles], eax
    mov [cycles+4], edx
    xor di, di
    mov cx, 0x8000
.verify_unrolled:
    mov ax, di
    cmp [es:di], al
    jne .bad_blit
    inc di
    loop .verify_unrolled
    mov dx, unrolled_timing
    mov ah, 9
    int 0x21
    mov eax, [cycles+4]
    call print_hex
    mov eax, [cycles]
    call print_hex
    mov dx, newline
    mov ah, 9
    int 0x21
    ; Register stores at 256 sites vary only their destination displacement.
    ; Masked instruction matching shares the three addressing-length forms.
    rdtsc
    mov [start_low], eax
    mov [start_high], edx
    xor di, di
    mov cx, 128
    mov al, 0x5a
.shared:
%assign pixel 0
%rep 256
    mov [es:di+pixel], al
%assign pixel pixel+1
%endrep
    add di, 256
    dec cx
    jz .shared_done
    jmp .shared
.shared_done:
    rdtsc
    sub eax, [start_low]
    sbb edx, [start_high]
    mov [cycles], eax
    mov [cycles+4], edx
    xor di, di
    mov cx, 0x8000
.verify_shared:
    cmp byte [es:di], 0x5a
    jne .bad_blit
    inc di
    loop .verify_shared
    mov dx, shared_timing
    mov ah, 9
    int 0x21
    mov eax, [cycles+4]
    call print_hex
    mov eax, [cycles]
    call print_hex
    mov dx, newline
    mov ah, 9
    int 0x21
    ; A register change must apply after the preceding write.
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
    ; Exercise the same stores in PM16 and PM32, including descriptor edits.
    mov ax, 1687h
    int 2fh
    test ax, ax
    jnz .bad_blit
    test si, si
    jnz .bad_blit
    mov [dpmi_entry], di
    mov [dpmi_entry+2], es
    mov ax, 1
    call far [dpmi_entry]
    jc .bad_blit
    movzx esp, sp
    mov byte [pm_active], 1
    mov ax, 2
    mov bx, 0xa000
    int 31h
    jc .bad_blit
    mov es, ax
    mov dx, 0x3ce
    mov ax, 0x0001       ; CPU data, no set/reset override
    out dx, ax
    mov di, 0x9003
    mov cx, 128
.pm16:
    mov [es:di], cx
    cmp [es:di], cx
    jne .bad_blit
    loop .pm16
    mov ax, 0x000a       ; alias CS, then turn it into 32-bit code
    mov bx, cs
    int 31h
    jc .bad_blit
    mov [pm32_entry+4], ax
    mov bx, ax
    mov ax, 9
    mov cx, 0x40fa
    int 31h
    jc .bad_blit
    call dword far [pm32_entry]
    cmp eax, 0x12345678
    jne .bad_blit
    mov ax, 7           ; change ES base without changing its selector
    mov bx, es
    mov cx, 0x000a
    mov dx, 0x0010
    int 31h
    jc .bad_blit
    mov word [es:di], 0xabc1
    cmp word [es:di], 0xabc1
    jne .bad_blit
    mov dx, pass
    jmp .print
.bad_bda:
    pop ds
.bad_blit:
    mov dx, fail
.print:
    cmp byte [pm_active], 0
    je .real_print
    call emit_pm
    jmp .hang
.real_print:
    mov ah, 9
    int 0x21
.hang:
    jmp .hang
emit_pm:
    mov [rmcs+20], dx
    mov dword [rmcs+28], 0900h
    mov ax, [rm_segment]
    mov [rmcs+36], ax
    push ds
    pop es
    mov edi, rmcs
    xor cx, cx
    mov bx, 21h
    mov ax, 0300h
    int 31h
    ret
rm_segment dw 0
pm_active db 0
rmcs times 50 db 0
bits 32
pm32_stores:
    mov edi, 0x9003
    mov ecx, 128
    mov eax, 0x12345678
.loop:
    mov [es:edi], eax
    cmp [es:edi], eax
    jne .bad
    loop .loop
    ; Bare and single-prefix forms exercise the static recipes directly.
    push ds
    push es
    pop ds
    mov ecx, 3
    mov [edi+ecx*2+17], eax      ; SIB + disp8
    cmp [edi+ecx*2+17], eax
    jne .bad_ds
    mov [ecx*2+0x9010], eax     ; SIB with no base: disp32 even with mod=00
    cmp [ecx*2+0x9010], eax
    jne .bad_ds
    mov dword [edi+ecx*4+0x1234], 0x87654321
    cmp dword [edi+ecx*4+0x1234], 0x87654321
    jne .bad_ds
    mov word [edi+31], 0xabcd   ; 66: 16-bit operand, 32-bit address
    a16 mov byte [di+31], 0x66 ; 67: 16-bit address, byte operand
    cmp word [edi+31], 0xab66
    jne .bad_ds
    mov [0x9020], eax           ; A3: address bytes are not lookup-key bits
    cmp dword [0x9020], eax
    jne .bad_ds
    mov [0x9024], al            ; A2
    cmp byte [0x9024], al
    jne .bad_ds
    pop ds
    retf
.bad_ds:
    pop ds
.bad:
    xor eax, eax
    retf
bits 16
pm32_entry dd pm32_stores
           dw 0
dpmi_entry dw 0, 0
patched_store:
    db 0x26, 0x88, 0x05       ; MOV [ES:DI], AL (patched above)
    ret
    times 4 db 0x90
other_cs dw patched_store, 0
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
unrolled_timing db 'EGA-UNROLLED-CYCLES=','$'
shared_timing db 'EGA-SHARED-CYCLES=','$'
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
