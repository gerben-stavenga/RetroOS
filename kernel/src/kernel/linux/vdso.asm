; One-page, position-independent ELF64 vDSO. No linker/runtime dependencies.
; Calibration at 0x800 is patched before the kernel makes the page read-only.
BITS 64
ORG 0
image:
    db 0x7f, 'ELF', 2, 1, 1, 0
    times 8 db 0
    dw 3, 62                    ; ET_DYN, EM_X86_64
    dd 1
    dq 0, phdrs, 0
    dd 0
    dw 64, 56, 2, 0, 0, 0
phdrs:
    dd 1, 5                     ; PT_LOAD, PF_R | PF_X
    dq 0, 0, 0, 4096, 4096, 4096
    dd 2, 4                     ; PT_DYNAMIC, PF_R
    dq dynamic, dynamic, dynamic, dynamic_end-dynamic, dynamic_end-dynamic, 8
align 8, db 0
dynamic:
    dq 5, strings
    dq 10, strings_end-strings
    dq 6, symbols
    dq 11, 24
    dq 4, hash
    dq 14, soname-strings
    dq 0x6ffffff0, versions
    dq 0x6ffffffc, version_def
    dq 0x6ffffffd, 1
    dq 0, 0
dynamic_end:
strings:
    db 0
clock_name: db '__vdso_clock_gettime', 0
alias_name: db 'clock_gettime', 0
version_name: db 'LINUX_2.6', 0
soname: db 'linux-vdso.so.1', 0
strings_end:
align 8, db 0
symbols:
    times 24 db 0
    dd clock_name-strings
    db 0x12, 0                  ; GLOBAL FUNC, DEFAULT
    dw 1
    dq clock_gettime, clock_end-clock_gettime
    dd alias_name-strings
    db 0x22, 0                  ; WEAK FUNC, DEFAULT
    dw 1
    dq clock_gettime, clock_end-clock_gettime
hash:
    dd 1, 3, 1, 0, 2, 0         ; bucket[0]=1; chains 1 -> 2 -> end
versions:
    dw 0, 2, 2
align 4, db 0
version_def:
    dw 1, 0, 2, 1
    dd 0x03ae75f6, 20, 0        ; ELF hash of LINUX_2.6, vd_aux, vd_next
    dd version_name-strings, 0
align 16, db 0
clock_gettime:
    ; Same clock IDs and millisecond precision as the kernel time service.
    cmp edi, 1                  ; CLOCK_MONOTONIC
    je .fast
    cmp edi, 4                  ; CLOCK_MONOTONIC_RAW
    je .fast
    cmp edi, 6                  ; CLOCK_MONOTONIC_COARSE
    je .fast
    cmp edi, 7                  ; CLOCK_BOOTTIME
    jne .syscall
.fast:
    test rsi, rsi
    jz .syscall
    lfence
    rdtsc
    shl rdx, 32
    or rax, rdx
    sub rax, [rel epoch]
    mul qword [rel multiplier]
    shrd rax, rdx, 32           ; low 64 bits of (cycles * multiplier) >> 32
    xor edx, edx
    mov ecx, 1000000000
    div rcx
    mov r8, rax                 ; seconds
    mov rax, rdx
    xor edx, edx
    mov ecx, 1000000
    div rcx
    imul rax, rcx               ; truncate fractional ns to whole milliseconds
    mov [rsi], r8
    mov [rsi+8], rax
    xor eax, eax
    ret
.syscall:
    mov eax, 228
    syscall
    ret
clock_end:
    times 0x800-($-image) db 0
epoch: dq 0
multiplier: dq 0
    times 4096-($-image) db 0
