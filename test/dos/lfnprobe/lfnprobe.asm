; Same guest ABI probe runs on FAT and ext4. CF is set before every LFN
; call, matching callers which must detect an unsupported 71xx service.
bits 16
org 100h
%macro lfn 1
    mov ax, %1
    stc
    int 21h
    jc fail
%endmacro
start:
    push cs
    pop ds
    push cs
    pop es
    cld
    mov dx, root
    mov di, buffer
    mov cx, 32
    lfn 71a0h
    test bx, 4000h
    jz fail
    test bx, 1
    jnz fail
    cmp cx, 255
    jne fail
    cmp dx, 260
    jne fail
    mov dx, root
    lfn 713bh

    mov byte [stage], '2'
    mov dx, directory
    lfn 7139h
    mov byte [stage], 'a'
    mov dx, directory_folded
    lfn 713bh
    mov byte [stage], 'b'
    xor dx, dx
    mov si, buffer
    lfn 7147h
    mov si, buffer
    mov di, directory
    call equal
    mov byte [stage], 'c'
    mov si, filename
    call create
    mov [file], ax
    mov bx, ax
    mov dx, payload
    mov cx, 7
    mov ah, 40h
    int 21h
    jc fail
    cmp ax, 7
    jne fail
    mov byte [stage], 'd'
    mov dx, info
    lfn 71a6h
    cmp dword [info+36], 7
    jne fail
    mov bx, [file]
    call close

    mov byte [stage], '3'
    mov si, filename_folded
    mov di, short_path
    mov cx, 1
    lfn 7160h
    mov dx, short_path
    mov ax, 3d00h
    int 21h
    jc fail
    mov bx, ax
    mov dx, buffer
    mov cx, 7
    mov ah, 3fh
    int 21h
    jc fail
    cmp ax, 7
    jne fail
    call close
    mov si, buffer
    mov di, payload
    mov cx, 7
    repe cmpsb
    jne fail
    mov si, short_path
    mov di, buffer
    mov cx, 2
    lfn 7160h
    mov si, buffer
    mov di, full_name
    call equal

    mov byte [stage], 't'
    mov dx, filename
    mov bx, 3
    mov cx, 6000h
    mov di, 5821h
    lfn 7143h
    mov bx, 4
    lfn 7143h
    cmp cx, 6000h
    jne fail
    cmp di, 5821h
    jne fail
    mov bx, 1
    mov cx, 21h
    lfn 7143h
    mov si, filename
    mov bx, 1
    xor cx, cx
    mov dx, 1
    mov ax, 716ch
    stc
    int 21h
    jnc fail
    cmp ax, 5
    jne fail
    mov dx, filename
    mov bx, 1
    mov cx, 20h
    lfn 7143h

    mov byte [stage], '4'
    mov dx, pattern
    xor cx, cx
    mov si, 1
    mov di, find_data
    lfn 714eh
    mov [search1], ax
    cmp dword [find_data+32], 7
    jne fail
    cmp dword [find_data+20], 58216000h
    jne fail
    mov si, find_data+44
    mov di, filename
    call equal
    cmp byte [guard], 0a5h
    jne fail
    mov dx, pattern
    xor cx, cx
    mov si, 0
    mov di, find_data
    lfn 714eh
    mov [search2], ax
    cmp ax, [search1]
    je fail
    mov bx, [search1]
    lfn 71a1h
    mov ax, 714fh
    mov si, 1
    mov di, find_data
    stc
    int 21h
    jnc fail
    cmp ax, 6
    jne fail
    mov bx, [search2]
    mov ax, 714fh
    stc
    int 21h
    jnc fail
    cmp ax, 18
    jne fail
    lfn 71a1h

    mov byte [stage], '5'
    mov dx, filename
    mov di, renamed
    lfn 7156h
    mov si, filename
    mov bx, 0
    mov cx, 0
    mov dx, 1
    mov ax, 716ch
    stc
    int 21h
    jnc fail
    cmp ax, 2
    jne fail
    mov dx, renamed
    xor si, si
    lfn 7141h

    ; >100-byte native component and legacy alias interoperability.
    mov byte [stage], '6'
    mov si, huge_name
    call create
    mov bx, ax
    call close
    mov si, huge_name
    mov di, short_path
    mov cx, 1
    lfn 7160h
    mov dx, short_path
    mov ax, 3d00h
    int 21h
    jc fail
    mov bx, ax
    call close
    mov dx, huge_name
    xor si, si
    lfn 7141h

    mov byte [stage], '7'
    mov si, accented
    call create
    mov bx, ax
    call close
    mov si, accented_upper
    mov bx, 0
    mov cx, 0
    mov dx, 1
    lfn 716ch
    mov bx, ax
    call close
    mov dx, accented_upper
    xor si, si
    lfn 7141h

    mov byte [stage], '8'
    mov si, unterminated
    mov bx, 2
    mov cx, 0
    mov dx, 10h
    mov ax, 716ch
    stc
    int 21h
    jnc fail
    cmp ax, 206
    jne fail
    mov dx, parent
    lfn 713bh
    mov dx, directory_folded
    lfn 713ah
    mov dx, success
    mov ah, 9
    int 21h
    mov ax, 4c00h
    jmp $

create:
    mov bx, 42h
    xor cx, cx
    mov dx, 10h
    lfn 716ch
    cmp cx, 2
    jne fail
    ret
close:
    mov ah, 3eh
    int 21h
    jc fail
    ret
equal:
    lodsb
    scasb
    jne fail
    test al, al
    jnz equal
    ret
fail:
    push ax
    mov dx, failure
    mov ah, 9
    int 21h
    pop bx
    mov cx, 4
.hex:
    rol bx, 4
    mov dl, bl
    and dl, 15
    add dl, '0'
    cmp dl, '9'
    jbe .emit
    add dl, 7
.emit:
    mov ah, 2
    int 21h
    loop .hex
    mov ax, 4c01h
    jmp $
root: db 'C:\',0
directory: db 'Long directory',0
directory_folded: db 'lONG DIRECTORY',0
filename: db 'Mixed case filename.txt',0
filename_folded: db 'mIXED CASE FILENAME.TXT',0
full_name: db 'C:\Long directory\Mixed case filename.txt',0
pattern: db '*case*.t?t',0
renamed: db 'Renamed long filename.txt',0
huge_name: times 200 db 'x'
    db '.txt',0
accented: db 'caf',82h,'.txt',0
accented_upper: db 'CAF',90h,'.TXT',0
unterminated: times 261 db 'x'
    db 0
parent: db '..',0
payload: db 'LFNDATA'
file: dw 0
search1: dw 0
search2: dw 0
failure: db 'LFN-FAIL stage='
stage: db '1',13,10,'$'
success: db 'LFN-ALL-OK',13,10,'$'
short_path: times 261 db 0
buffer: times 261 db 0
info: times 52 db 0
find_data: times 318 db 0
guard: db 0a5h
