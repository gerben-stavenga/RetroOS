; Kernel GS must never replace guest TLS across faults, syscalls, or IRQs.
; Build as ELF32, or ELF64 with -DCLIENT64.
%ifdef CLIENT64
bits 64
%else
bits 32
%endif
global _start
section .text
_start:
    mov ebp, 32
.round:
%ifdef CLIENT64
    ; Exercise all 64 bits of GS_BASE, not just a low-address selector base.
    mov r12, -0x100000000
    mov rsi, tls_data + 0x100000000
    mov edi, 0x1001             ; ARCH_SET_GS
    mov eax, 158
    syscall
    test eax, eax
    jnz .fail
    mov esi, tls_data
    mov edi, 0x1002             ; ARCH_SET_FS
    mov eax, 158
    syscall
    test eax, eax
    jnz .fail
    cmp dword [gs:r12], 0x13572468
    jne .fail
    cmp dword [fs:4], 0x24681357
    jne .fail
    mov edi, 0x1004             ; ARCH_GET_GS must preserve the high bits too
    mov esi, observed_base
    mov eax, 158
    syscall
    mov rax, tls_data + 0x100000000
    cmp [observed_base], rax
    jne .fail
%else
    mov eax, 243                ; set_thread_area modifies guest GDT TLS
    mov ebx, descriptor
    int 0x80
    test eax, eax
    jnz .fail
    mov eax, [descriptor]
    lea eax, [eax*8+3]
    mov gs, ax
    mov fs, ax
    cmp dword [gs:0], 0x13572468
    jne .fail
    cmp dword [fs:4], 0x24681357
    jne .fail
%endif
    ; Timer IRQs can interrupt user code with non-kernel GS installed.
    mov ebx, 200000
.spin:
%ifdef CLIENT64
    cmp dword [gs:r12], 0x13572468
%else
    cmp dword [gs:0], 0x13572468
%endif
    jne .fail
    dec ebx
    jnz .spin
    ; Sleeping also forces timer-driven kernel progress while we are parked.
%ifdef CLIENT64
    mov eax, 35                 ; nanosleep
    mov edi, delay
    xor esi, esi
    syscall
%else
    mov eax, 162
    mov ebx, delay
    xor ecx, ecx
    int 0x80
%endif
    test eax, eax
    jnz .fail
%ifdef CLIENT64
    cmp dword [gs:r12], 0x13572468
%else
    cmp dword [gs:0], 0x13572468
%endif
    jne .fail
    cmp dword [fs:4], 0x24681357
    jne .fail
    dec ebp
    jnz .round
    xor ebx, ebx
    jmp .exit
.fail:
    mov ebx, 1
.exit:
%ifdef CLIENT64
    mov edi, ebx
    mov eax, 60
    syscall
%else
    mov eax, 1
    int 0x80
%endif
    ud2

section .data
tls_data: dd 0x13572468, 0x24681357
%ifndef CLIENT64
descriptor: dd -1, tls_data, 0xfffff, 0x51
delay: dd 0, 2000000
%else
delay: dq 0, 2000000
observed_base: dq 0
%endif
