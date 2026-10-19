bits 16
org 0x100
    push cs
    pop es
    mov dl, 2
    mov ah, 0x0e
    int 0x21
    mov dx, directory
    mov ah, 0x3b
    int 0x21
    mov dx, program
    mov bx, tail
    xor cx, cx
    mov ah, 1
    int 0x31
    jc failed
    ; A foreground Linux application must not schedule this ready launcher
    ; just because it yields or waits. Consume any misrouted keyboard input.
idle:
    mov ah, 8
    int 0x21
    jmp idle
failed:
    mov ax, 0x4c01
    int 0x21
program db 'C:\PROBE.ELF', 0
directory db 'C:\RETROOS', 0
tail db 0
