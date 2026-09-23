; EMS aliases, saved maps and cross-page moves used by Aladdin.
bits 16
org 100h

%macro ems 1
    mov ax, %1
    int 67h
    test ah, ah
    jnz fail
%endmacro
%macro expect_error 2
    mov ax, %1
    int 67h
    cmp ah, %2
    jne fail
%endmacro

start:
    push cs
    pop ds
    ems 4100h
    mov es, bx
    mov [frame], bx
    mov bx, 3
    ems 4300h
    mov [handle], dx

    ; Both windows must alias the same storage immediately.
    mov byte [stage], 'A'
    xor bx, bx
    ems 4400h
    ems 4401h
    mov word [es:0], 1234h
    cmp word [es:4000h], 1234h
    jne fail
    mov word [es:4002h], 5678h
    cmp word [es:2], 5678h
    jne fail
    ; Replacing one alias must not swap the other one's data away.
    mov bx, 1
    ems 4400h
    mov word [es:0], 9abch
    cmp word [es:4000h], 1234h
    jne fail
    xor bx, bx
    ems 4400h
    cmp word [es:0], 1234h
    jne fail

    mov byte [stage], 'S'
    expect_error 4800h, 8eh
    ems 4700h
    expect_error 4700h, 8dh
    mov bx, 1
    ems 4400h
    mov bx, 2
    ems 4401h
    ems 4800h
    cmp word [es:0], 1234h
    jne fail
    cmp word [es:4002h], 5678h
    jne fail
    expect_error 4800h, 8eh

    ; Invalid multi-map entries leave that window intact; earlier successful
    ; entries remain applied. Segment mappings must name exact window starts.
    mov byte [stage], 'V'
    mov si, maps
    mov cx, 2
    expect_error 5000h, 8ah
    cmp word [es:0], 9abch
    jne fail
    cmp word [es:4000h], 1234h
    jne fail
    mov cx, 1
    mov word [maps+2], 100h
    expect_error 5000h, 8bh
    mov bx, [frame]
    inc bx
    mov [maps+2], bx
    expect_error 5001h, 8bh
    expect_error 5002h, 8fh
    xor bx, bx
    ems 4400h

    ; Fill a conventional source, then move it across two expanded pages.
    mov byte [stage], 'M'
    mov di, buffer
    mov cx, 40h
    xor ax, ax
.fill:
    mov [di], ax
    inc ax
    add di, 2
    loop .fill
    mov ax, ds
    mov [region+9], ax
    mov ax, [handle]
    mov [region+12], ax
    mov si, region
    ems 5700h
    mov dx, [handle]
    mov bx, 1
    ems 4402h
    mov bx, 2
    ems 4403h
    xor bx, bx
.check:
    mov di, bx
    shl di, 1
    cmp [es:di+0bfd0h], bx
    jne fail
    inc bx
    cmp bx, 40h
    jne .check
    ; Move expanded data back through a different conventional buffer.
    mov byte [region+4], 1
    mov ax, [handle]
    mov [region+5], ax
    mov word [region+7], 3fd0h
    mov word [region+9], 1
    mov byte [region+11], 0
    mov word [region+14], other
    mov ax, ds
    mov [region+16], ax
    ems 5700h
    xor bx, bx
.check_back:
    mov di, bx
    shl di, 1
    cmp [di+other], bx
    jne fail
    inc bx
    cmp bx, 40h
    jne .check_back
    ; Exchange a conventional buffer and the expanded region.
    mov word [other], 4321h
    ems 5701h
    cmp word [other], 0
    jne fail
    cmp word [es:0bfd0h], 4321h
    jne fail

    ; Overlapping moves still copy, with a warning. Exchange must reject
    ; overlap without mutation, including overlap via a page-frame alias.
    mov byte [stage], 'O'
    mov word [region+14], 0bfd2h
    mov ax, [frame]
    mov [region+16], ax
    expect_error 5701h, 94h
    cmp word [es:0bfd2h], 1
    jne fail
    expect_error 5700h, 94h
    cmp word [es:0bfd2h], 4321h
    jne fail
    cmp word [es:0bfd4h], 1
    jne fail
    mov byte [region+11], 1
    mov word [region+14], 3fd2h
    mov word [region+16], 1
    expect_error 5701h, 97h
    expect_error 5700h, 92h
    cmp word [es:0bfd4h], 4321h
    jne fail
    mov word [region+7], 4000h
    expect_error 5700h, 95h
    mov word [region+7], 3ff0h
    mov word [region+9], 2
    expect_error 5700h, 93h
    mov word [region+9], 3
    expect_error 5700h, 8ah
    mov byte [region+4], 2
    expect_error 5700h, 98h
    expect_error 5702h, 8fh
    mov dword [region], 100001h
    expect_error 5700h, 96h
    mov dword [region], 80h
    mov byte [region+4], 0
    mov word [region+7], 0fff0h
    mov word [region+9], 0ffffh
    expect_error 5700h, 0a2h
    mov word [region+7], buffer
    mov ax, ds
    mov [region+9], ax
    mov dword [region], 0
    ems 5700h
    ems 5701h

    ; Force a relocation on growth by putting another handle after this one.
    mov byte [stage], 'R'
    mov bx, 1
    ems 4300h
    mov [blocker], dx
    mov dx, [handle]
    ems 4700h
    mov bx, 5
    ems 5100h
    cmp word [es:0], 1234h
    jne fail
    mov word [es:4004h], 0a55ah
    cmp word [es:4], 0a55ah
    jne fail
    ems 4800h
    cmp word [es:4004h], 0a55ah
    jne fail
    ; Shrink drops only removed pages and preserves surviving aliases.
    mov bx, 1
    ems 5100h
    cmp word [es:0], 1234h
    jne fail
    cmp word [es:4004h], 0a55ah
    jne fail
    ems 4500h
    mov dx, [blocker]
    ems 4500h
    mov dx, pass_msg
    mov ah, 9
    int 21h
    mov ax, 4c00h
    int 21h
fail:
    push cs
    pop ds
    mov dx, fail_msg
    mov ah, 9
    int 21h
    mov dl, [stage]
    mov ah, 2
    int 21h
    mov ax, 4c01h
    int 21h

frame dw 0
handle dw 0
blocker dw 0
stage db '0'
pass_msg db 'EMSPROBE PASS',13,10,'$'
fail_msg db 'EMSPROBE FAIL stage $'
maps dw 1,0, 3,1
region:
    dd 80h
    db 0
    dw 0, buffer, 0
    db 1
    dw 0, 3fd0h, 1
buffer times 80h db 0
other times 80h db 0
