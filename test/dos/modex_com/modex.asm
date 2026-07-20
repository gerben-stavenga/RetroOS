; MODEX.COM — Mode X (unchained planar 320x200) test for the VGA planar trap.
;
; Draws three horizontal bands so a screenshot tells pass/fail at a glance:
;   rows   0..49  multi-plane fill (Map Mask = 0x0F, write mode 0): every pixel
;                 should be solid green 0x2A. Under the broken single-plane
;                 alias only every 4th column updates -> green 1px stripes.
;   rows  50..99  single-plane control (Map Mask = 0x01): only plane 0, so red
;                 0x0C 1px stripes BY DESIGN — confirms the renderer's Mode X
;                 plane layout. Looks the same fixed or broken.
;   rows 150..199 latched copy (write mode 1) of the top band: should reproduce
;                 the solid green band. Broken alias copies one plane -> stripes.
;
; In Mode X pixel (x,y) is plane (x&3) at byte y*80 + x/4, so 4000 bytes = 50
; rows. PSP int20 stub on exit; we just hang so the frame is captured.

org 0x100

    mov ax, 0x0013          ; mode 13h (sets up DAC, 320x200x256 linear)
    int 0x10

    ; Unchain: Sequencer Memory Mode (index 4), clear chain-4 (bit 3) -> 0x06.
    mov dx, 0x3C4
    mov ax, 0x0604
    out dx, ax

    mov ax, 0x0A000
    mov es, ax

    ; --- band 1: multi-plane solid fill (rows 0..49) ---
    mov dx, 0x3C4
    mov ax, 0x0F02          ; Map Mask (idx 2) = 0x0F (all planes)
    out dx, ax
    xor di, di
    mov cx, 4000
    mov al, 0x2A            ; light green
    rep stosb               ; write mode 0, all planes -> solid

    ; --- band 2: single-plane control (rows 50..99) ---
    mov dx, 0x3C4
    mov ax, 0x0102          ; Map Mask = plane 0 only
    out dx, ax
    mov di, 80*50
    mov cx, 4000
    mov al, 0x0C            ; red
    rep stosb               ; only plane 0 updates -> 1px stripes (by design)

    ; --- band 3: latched copy of band 1 down to rows 150..199 ---
    mov dx, 0x3CE
    mov ax, 0x0105          ; Graphics Mode (idx 5), write mode 1 (latched copy)
    out dx, ax
    mov dx, 0x3C4
    mov ax, 0x0F02          ; Map Mask = all planes (copy to all)
    out dx, ax
    xor si, si              ; src = top band
    mov di, 80*150          ; dst = rows 150..
    mov cx, 4000
.copy:
    mov al, [es:si]         ; read loads the 4 latches
    mov [es:di], al         ; write mode 1 stores the latches (CPU al ignored)
    inc si
    inc di
    loop .copy

    ; restore write mode 0 (be a tidy citizen) and hang for the screenshot.
    mov dx, 0x3CE
    mov ax, 0x0005
    out dx, ax
.hang:
    jmp .hang
