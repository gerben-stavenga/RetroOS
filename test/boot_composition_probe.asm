; Same C: composition on RAM-module and EFI/FAT boot sources.
bits 16
org 100h
%macro check 3
    mov byte [stage], %3
    mov dx, %1
    mov ax, 3d00h
    int 21h
    jc fail
    mov bx, ax
    mov dx, buffer
    mov cx, 1
    mov ah, 3fh
    int 21h
    jc fail
    cmp ax, 1
    jne fail
    cmp byte [buffer], %2
    jne fail
    mov ah, 3eh
    int 21h
%endmacro
%macro write 3
    mov byte [stage], %3
    mov dx, %1
    mov ax, 3d02h
    int 21h
    jc fail
    mov bx, ax
    mov byte [buffer], %2
    mov dx, buffer
    mov cx, 1
    mov ah, 40h
    int 21h
    jc fail
    cmp ax, 1
    jne fail
    mov ah, 3eh
    int 21h
%endmacro
start:
    push cs
    pop ds
    push cs
    pop es
    check data, 'D', '1'
    check runtime, 'B', '2'
    check override, 'D', '3'
    check default_file, 'B', '4'
    check nested, 'B', '5'
    mov byte [stage], '6'
    mov dx, oldtemp
    mov ax, 3d00h
    int 21h
    jnc fail
    mov byte [stage], '7'
    mov dx, newtemp
    xor cx, cx
    mov ah, 3ch
    int 21h
    jc fail
    mov bx, ax
    mov ah, 3eh
    int 21h
    write newtemp, 'T', '8'
    check newtemp, 'T', '9'
    mov byte [stage], 'A'
    mov dx, newtemp
    mov di, movedtemp
    mov ah, 56h
    int 21h
    jc fail
    mov dx, movedtemp
    mov ah, 41h
    int 21h
    jc fail
    write override, 'S', 'B'
    write default_file, 'R', 'C'
    check default_file, 'R', 'D'
    mov byte [stage], 'E'
    mov dx, runtime
    mov ax, 3d02h
    int 21h
    jc protected
    mov bx, ax
    mov dx, buffer
    mov cx, 1
    mov ah, 40h
    int 21h
    jc protected
    test ax, ax
    jnz fail
protected:
    mov dx, success
    mov ah, 9
    int 21h
    mov ax, 4c00h
    int 21h
fail:
    mov dx, failure
    mov ah, 9
    int 21h
    mov dl, [stage]
    mov ah, 2
    int 21h
    mov ax, 4c01h
    int 21h
stage db '?'
buffer db 0
data db 'C:\DATA.TXT',0
runtime db 'C:\RETROOS\RUNTIME.TXT',0
override db 'C:\CONFIG\OVERRIDE.TXT',0
default_file db 'C:\CONFIG\DEFAULT.TXT',0
nested db 'C:\CONFIG\NESTED\DEFAULT.TXT',0
oldtemp db 'C:\TEMP\OLD.TXT',0
newtemp db 'C:\TEMP\NEW.TXT',0
movedtemp db 'C:\TEMP\MOVED.TXT',0
success db 'COMPOSITION-OK',13,10,'$'
failure db 'COMPOSITION-FAIL $'
