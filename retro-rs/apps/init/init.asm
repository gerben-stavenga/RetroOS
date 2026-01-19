; Minimal init process
; Just prints a message and halts

[bits 32]
section .text
global _start

_start:
    ; Write "Init!" to screen via syscall
    ; syscall 9 = write
    ; edx = fd (1 = stdout)
    ; ecx = buffer
    ; ebx = length
    mov eax, 9          ; sys_write
    mov edx, 1          ; fd = stdout
    mov ecx, message    ; buffer
    mov ebx, message_len; length
    int 0x80

    ; Exit with code 0
    mov eax, 0          ; sys_exit
    mov edx, 0          ; exit code
    int 0x80

    ; Should not reach here
.halt:
    jmp .halt

section .rodata
message: db "Hello from init!", 10
message_len equ $ - message
