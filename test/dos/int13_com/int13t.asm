; INT 13h floppy probe: AH=08 params, AH=02 boot-sector read + 55AA check,
; AH=16 change line twice, AH=03 write must report write-protect.
org 0x100
start:
    ; AH=08: drive params for A:
    mov ah, 0x08
    mov dl, 0
    xor di, di
    mov es, di
    int 0x13
    jc  fail8
    mov [drtype], bl
    mov al, cl
    and al, 0x3F
    mov [spt], al
    mov dx, msg8ok
    call print
    ; print BL (drive type) and SPT as hex digits
    mov al, [drtype]
    call printhex
    mov al, [spt]
    call printhex
    call newline

    ; AH=02: read C0 H0 S1 (boot sector) to buf. AH=08 pointed ES:DI at
    ; the DDPT, so restore ES to our segment first.
    push cs
    pop es
    mov ax, 0x0201
    mov cx, 0x0001
    mov dx, 0x0000
    mov bx, buf
    int 0x13
    jc  fail2
    cmp word [buf+510], 0xAA55
    jne failsig
    mov dx, msg2ok
    call print
    call newline

    ; AH=16: change line — expect 06 the first time (just inserted), 00 after
    mov ah, 0x16
    mov dl, 0
    int 0x13
    mov al, ah
    call printhex
    mov ah, 0x16
    mov dl, 0
    int 0x13
    mov al, ah
    call printhex
    call newline

    ; AH=03: write one sector — must fail with AH=03 write-protected
    mov ax, 0x0301
    mov cx, 0x0001
    mov dx, 0x0000
    mov bx, buf
    int 0x13
    jnc failwr
    mov al, ah
    call printhex
    mov dx, msgwp
    call print
    call newline
    int 0x20

fail8:  mov dx, msgf8
        jmp short die
fail2:  mov dx, msgf2
        jmp short die
failsig: mov dx, msgfs
        jmp short die
failwr: mov dx, msgfw
die:    call print
        call newline
        int 0x20

print:  mov ah, 0x09
        int 0x21
        ret
newline: mov dx, crlf
        jmp print
printhex:
        push ax
        shr al, 4
        call nib
        pop ax
nib:    and al, 0x0F
        add al, '0'
        cmp al, '9'
        jbe .out
        add al, 7
.out:   mov dl, al
        mov ah, 0x02
        int 0x21
        ret

msg8ok: db 'PARAMS OK TYPE+SPT=$'
msg2ok: db 'BOOTSECT 55AA OK$'
msgwp:  db '=WRITEPROT OK$'
msgf8:  db 'FAIL AH08$'
msgf2:  db 'FAIL AH02$'
msgfs:  db 'FAIL SIG$'
msgfw:  db 'FAIL WRITE ACCEPTED$'
crlf:   db 13, 10, '$'
drtype: db 0
spt:    db 0
buf:
