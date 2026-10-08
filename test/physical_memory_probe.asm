; Native Linux ABI probe: touch and release 300 MiB twice. With QEMU's
; below-4-GiB RAM limited to 128 MiB this requires high physical pages.
%ifdef CLIENT64
bits 64
%define PTR rax
%define INDEX rdi
%define PTR_SIZE qword
%else
bits 32
%define PTR eax
%define INDEX edi
%define PTR_SIZE dword
%endif
global _start
section .text
_start:
    mov dword [rounds], 2
.allocate:
%ifdef CLIENT64
    mov eax, 9                   ; mmap
    xor edi, edi
    mov esi, 300 * 1024 * 1024
    mov edx, 3
    mov r10d, 0x22
    mov r8, -1
    xor r9d, r9d
    syscall
%else
    mov eax, 192                 ; mmap2
    xor ebx, ebx
    mov ecx, 300 * 1024 * 1024
    mov edx, 3
    mov esi, 0x22                ; private, anonymous
    mov edi, -1
    xor ebp, ebp
    int 0x80
%endif
    cmp PTR, -4095
    jae .fail
    mov PTR_SIZE [base], PTR
    mov INDEX, PTR
    mov ecx, 300 * 256
.write:
    mov byte [INDEX], 0x5a
    add INDEX, 4096
    loop .write
    mov INDEX, PTR_SIZE [base]
    mov ecx, 300 * 256
.check:
    cmp byte [INDEX], 0x5a
    jne .fail
    add INDEX, 4096
    loop .check
%ifdef CLIENT64
    mov eax, 11                  ; munmap
    mov rdi, [base]
    mov esi, 300 * 1024 * 1024
    syscall
%else
    mov eax, 91                  ; munmap
    mov ebx, [base]
    mov ecx, 300 * 1024 * 1024
    int 0x80
%endif
    test eax, eax
    jnz .fail
    dec dword [rounds]
    jnz .allocate
    mov ecx, pass
    mov edx, pass_len
    call .write_message
.done:
%ifdef CLIENT64
    mov eax, 60
    xor edi, edi
    syscall
%else
    mov eax, 1                   ; exit success; native lifecycle log is the oracle
    xor ebx, ebx
    int 0x80
%endif
.fail:
    mov ecx, fail
    mov edx, fail_len
    call .write_message
%ifdef CLIENT64
    mov eax, 60
    mov edi, 1
    syscall
%else
    mov eax, 1
    mov ebx, 1
    int 0x80
%endif
.write_message:
%ifdef CLIENT64
    mov eax, 1
    mov rsi, rcx
    mov edi, 1
    syscall
%else
    mov eax, 4
    mov ebx, 1
    int 0x80
%endif
    ret
section .rodata
pass: db 'PHYSICAL-MEMORY-PASS', 10
pass_len equ $ - pass
fail: db 'PHYSICAL-MEMORY-FAIL', 10
fail_len equ $ - fail
section .bss
base: resq 1
rounds: resd 1
