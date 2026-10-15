; DOS installs both entries only during planar execution. The normal fault
; path admits MOVs into a CS:IP + mode allow list; hits never call Rust.
section .note.GNU-stack noalloc noexec nowrite progbits
section .text
extern PLANAR_FAST_WRITES
extern entry_wrapper_32
extern entry_wrapper_64

; Rust repr(C) layout, asserted in planar.rs.
BATCH equ 2048
CAPACITY equ 256
COUNT equ BATCH + CAPACITY * 12

; Instruction = identity + gpr_index. Identity caches CS:IP, mode,
; expected bytes, linear code address and instruction length.
INS_IP equ 0
INS_CS_MODE equ 4
INS_CODE equ 8
INS_ADDRESS equ 16
INS_LEN equ 20
INS_GPR equ 24
PROTECTED equ 1 << 20
CODE32 equ 1 << 22

STORE_ADDRESS equ 0
STORE_REG equ 4
STORE_INS_ID equ 8

%macro planar_handler 1
[bits %1]
global planar_page_fault_%1
planar_page_fault_%1:
%if %1 == 32
    %define SP esp
    %define PTR ss:
    %assign ERROR 36
    %assign IP 40
    %assign CS 44
    %assign FLAGS 48
    push dword 14
    pushad
%else
    %define SP rsp
    %define PTR
    %assign ERROR 64
    %assign IP 72
    %assign CS 80
    %assign FLAGS 88
    push qword 14
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
%endif
    mov eax, [SP + ERROR]
    and eax, ~1               ; user write; no fetch/reserved-bit fault
    cmp eax, 6
    jne .slow
    test byte [SP + FLAGS + 1], 1 ; single stepping
    jnz .slow
%if %1 == 32
    mov eax, cr2
    lea edx, [eax - 0xa0000]
    cmp edx, 0x10000
    mov ebx, [ss:PLANAR_FAST_WRITES]
%else
    mov rax, cr2
    lea rdx, [rax - 0xa0000]
    cmp rdx, 0x10000
    mov ebx, [rel PLANAR_FAST_WRITES]
%endif
    jae .slow
    movzx ecx, word [SP + CS]
%if %1 == 32
    test dword [SP + FLAGS], 1 << 17
    jnz .key_ready            ; VM86 mode = 0
%endif
    or ecx, PROTECTED
.key_ready:
    mov edx, [SP + IP]
    mov esi, edx
    xor esi, ecx
    and esi, 63
    shl esi, 5
    add esi, ebx
    cmp edx, [PTR esi + INS_IP]
    jne .slow
    ; Descriptor edits clear the cache. With an unchanged selector its
    ; recorded D-bit remains valid; only VM86/protected can differ here.
    mov edi, [PTR esi + INS_CS_MODE]
    and edi, ~CODE32
    cmp ecx, edi
    jne .slow
    mov edi, [PTR esi + INS_ADDRESS]
%if %1 == 32
    mov ecx, [ss:edi]
    cmp ecx, [ss:esi + INS_CODE]
    jne .slow
    mov ecx, [ss:edi + 4]
    cmp ecx, [ss:esi + INS_CODE + 4]
%else
    mov rcx, [rdi]
    cmp rcx, [rsi + INS_CODE]
%endif
    jne .slow
    ; A split access can fault on its second page: CR2 is then not the
    ; start address. Keep page-edge accesses on the normal decoder.
    mov edx, eax
    and edx, 0xfff
    sub edx, 3
    cmp edx, 0xff9
    ja .slow
    cmp dword [PTR ebx + COUNT], CAPACITY
    jae .slow

    ; Capture one full GPR, or nothing for an immediate instruction.
    xor ecx, ecx
    movzx edx, byte [PTR esi + INS_GPR]
    cmp edx, 255
    je .captured
    movzx edx, byte [PTR .gpr_offsets + edx]
%if %1 == 32
    mov ecx, [esp + edx]
%else
    mov ecx, [rsp + rdx]
%endif
.captured:
    ; Append { CR2, captured GPR, instruction ID } at buf[len].
    mov edx, [PTR ebx + COUNT]
    lea edx, [edx + edx * 2]
    lea edx, [ebx + edx * 4 + BATCH]
    mov [PTR edx + STORE_ADDRESS], eax
    mov [PTR edx + STORE_REG], ecx
    mov edi, esi
    sub edi, ebx
    shr edi, 5
    mov [PTR edx + STORE_INS_ID], di
    inc dword [PTR ebx + COUNT]

    ; Advance IP; VM86 and 16-bit protected code wrap at 64 KiB.
    movzx ecx, byte [PTR esi + INS_LEN]
    add ecx, [SP + IP]
    test dword [PTR esi + INS_CS_MODE], CODE32
    jnz .ip_ready
    and ecx, 0xffff
.ip_ready:
    mov [SP + IP], ecx
%if %1 == 32
    mov bx, 0x48              ; ordinary 16-bit-stack ESPFIX contract
    mov ss, bx
    movzx esp, sp
    popad
    add esp, 8
    iretd
.slow:
    popad
    jmp entry_wrapper_32
%else
    ; Keep the success branch flag across POPs, so restoration is shared.
    xor edx, edx
    jmp .restore
.slow:
    mov edx, 1
.restore:
    test edx, edx
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    jnz .full_frame
    lea rsp, [rsp + 16]
    iretq
.full_frame:
    jmp entry_wrapper_64
%endif
; x86 GPR encoding: AX, CX, DX, BX, SP, BP, SI, DI.
.gpr_offsets:
%if %1 == 32
    db 28, 24, 20, 16, 52, 8, 4, 0
%else
    db 48, 40, 32, 24, 96, 16, 8, 0
%endif
%endmacro

planar_handler 32
planar_handler 64
