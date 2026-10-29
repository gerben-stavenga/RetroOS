; Dedicated planar MOV entry. Save only GPRs and the selectors needed by
; Rust on unsupported forms only. Static recipes work on the first fault.
section .note.GNU-stack noalloc noexec nowrite progbits
section .text
extern PLANAR_FAST_CONTEXT
extern planar_fault
extern entry_wrapper_32
extern entry_wrapper_64

; Fast descriptor offsets are asserted in Rust. Decode-table entries are
; { normalized_key: u16, recipe: u16 }, two entries per bucket.
%macro account_fast 0
    cmp dword [PTR ebx + 40], 0
    je %%done
    rdtsc
    sub eax, [PTR ebx + 52]
    sbb edx, [PTR ebx + 56]
    add [PTR ebx + 44], eax
    adc [PTR ebx + 48], edx
%%done:
%endmacro

%macro fast_store 0
    %define PTR ss:
    mov ebx, [ss:PLANAR_FAST_CONTEXT]
    test ebx, ebx
    jz %%rust
    cmp dword [PTR ebx], 0
    je %%rust
    cmp dword [PTR ebx + 60], 0
    jne %%rust               ; synchronous scanout needs a phase check first
    cmp dword [ss:esp + 4], 0
    jne %%cs64
    movzx ecx, word [ss:ebp + 76]
    test dword [ss:ebp + 80], 1 << 17
    jnz %%cs_ready
    jmp %%protected
%%cs64:
    movzx ecx, word [ss:ebp + 88]
%%protected:
    or ecx, 1 << 20
%%cs_ready:
    cmp ecx, [PTR ebx + 8]
    jne %%miss
    mov edi, [ss:ebp + 72]
    cmp dword [ss:esp + 4], 0
    je %%ip_loaded
    mov edi, [ss:ebp + 80]
%%ip_loaded:
    cmp dword [PTR ebx + 12], 0
    jne %%ip_ready
    and edi, 0xffff
    cmp edi, 0xfff0
    ja %%miss
%%ip_ready:
    mov eax, edi
    add eax, 15
    jc %%miss
    cmp eax, [PTR ebx + 20]
    ja %%miss
    add edi, [PTR ebx + 16]
    jc %%miss
    mov eax, edi
    and eax, 0xfff
    cmp eax, 0xff0
    ja %%miss                ; never fetch another code page

    movzx eax, word [PTR edi]
    movzx ecx, al
    mov edx, ecx
    and edx, 0xe7
    cmp edx, 0x26          ; ES/CS/SS/DS prefixes
    je %%key
    lea edx, [ecx - 0x64]
    cmp edx, 3             ; FS/GS, operand/address-size prefixes
    jbe %%key
    mov eax, ecx           ; bare opcode: second byte is read by the recipe
%%key:
    mov edx, eax
    imul eax, 0xd64148c7   ; same hash as the compile-time table builder
    shr eax, 26
    mov esi, [PTR ebx + 4]
    lea esi, [esi + eax * 8]
    cmp dx, [PTR esi]
    je %%recipe
    add esi, 4
    cmp dx, [PTR esi]
    jne %%miss
%%recipe:
    movzx esi, word [PTR esi + 2]
    test esi, esi
    jz %%miss
    push edi               ; instruction start, later replaced by its length
    mov ecx, esi
    shr ecx, 6
    add edi, ecx           ; skip the optional prefix
    inc edi                ; opcode
    test esi, 32
    jnz %%moffs

    movzx edx, byte [PTR edi]
    inc edi
    cmp edx, 0xc0
    jae %%reject           ; register-only ModRM cannot be a VGA store
    test esi, 16
    jz %%source
    test dl, 0x38          ; C6/C7 require /0
    jnz %%reject
%%source:
    mov eax, edx
    and eax, 0x38
    shl eax, 5
    or esi, eax            ; source register in recipe bits 8..10
    mov ecx, edx
    shr ecx, 6             ; displacement form (mod)
    and edx, 7             ; r/m
    test esi, 8
    jz %%addr16
    cmp edx, 4
    jne %%addr32
    movzx edx, byte [PTR edi] ; SIB: only base affects displacement length
    inc edi
    and edx, 7
%%addr32:
    cmp ecx, 1
    je %%disp8
    cmp ecx, 2
    je %%disp32
    cmp edx, 5
    je %%disp32
    jmp %%operand
%%addr16:
    cmp ecx, 1
    je %%disp8
    cmp ecx, 2
    je %%disp16
    cmp edx, 6
    je %%disp16
    jmp %%operand
%%moffs:
    test esi, 8
    jnz %%disp32
%%disp16:
    add edi, 2
    jmp %%operand
%%disp32:
    add edi, 4
    jmp %%operand
%%disp8:
    inc edi
%%operand:
    test esi, 16
    jnz %%immediate
    mov ecx, esi
    shr ecx, 8
    test esi, 1            ; byte source: 4..7 mean AH..BH
    jz %%register
    test cl, 4
    jz %%register
    and ecx, 3
    mov eax, [ss:ebp + ecx * 8]
    shr eax, 8
    jmp %%value
%%register:
    mov eax, [ss:ebp + ecx * 8]
    jmp %%value
%%immediate:
    mov ecx, esi
    and ecx, 7
    cmp ecx, 1
    jne %%imm_wide
    movzx eax, byte [PTR edi]
    jmp %%imm_loaded
%%imm_wide:
    cmp ecx, 2
    jne %%imm32
    movzx eax, word [PTR edi]
    jmp %%imm_loaded
%%imm32:
    mov eax, [PTR edi]
%%imm_loaded:
    add edi, ecx
%%value:
    sub edi, [ss:esp]
    mov [ss:esp], edi      ; instruction length, never an immediate value
    and esi, 7             ; operand width
    mov edx, cr2
    cmp edx, [PTR ebx + 28]
    jb %%reject
    lea ecx, [edx + esi]
    cmp ecx, edx
    jb %%reject
    cmp ecx, [PTR ebx + 32]
    ja %%reject
    mov ecx, edx
    and ecx, 0xfff
    cmp ecx, 3
    jb %%reject            ; CR2 can name the second page of a split operand
    cmp ecx, 0xffc
    ja %%reject
    mov edi, edx
    sub edi, [PTR ebx + 28]
    and edi, 0xffff
    shl edi, 2
    add edi, [PTR ebx + 24]
    mov edx, [PTR ebx + 36]
    mov ecx, esi
%%byte:
    test dl, 1
    jz %%plane1
    mov [PTR edi], al
%%plane1:
    test dl, 2
    jz %%plane2
    mov [PTR edi + 1], al
%%plane2:
    test dl, 4
    jz %%plane3
    mov [PTR edi + 2], al
%%plane3:
    test dl, 8
    jz %%stored
    mov [PTR edi + 3], al
%%stored:
    add edi, 4
    shr eax, 8
    dec ecx
    jnz %%byte
    pop eax                ; instruction length; restore common-entry stack
    lea edi, [ebp + 72]
    cmp dword [ss:esp + 4], 0
    je %%ip_target
    lea edi, [ebp + 80]
%%ip_target:
    add eax, [PTR edi]
    cmp dword [PTR ebx + 12], 0
    jne %%advance
    and eax, 0xffff
%%advance:
    mov [PTR edi], eax
    mov eax, 1
    jmp planar_return
%%reject:
    add esp, 4             ; discard decode scratch before Rust dispatch
%%miss:
%%rust:
%endmacro

bits 32
; Leave odd u32 slots undefined; only each register's low half is accessed.
%macro save32 1
    sub esp, 4
    push %1
%endmacro
%macro restore32 1
    pop %1
    add esp, 4
%endmacro
%macro restore_gprs32 0
    restore32 eax
    restore32 ecx
    restore32 edx
    restore32 ebx
    add esp, 8             ; guest ESP lives in the CPU return frame
    restore32 ebp
    restore32 esi
    restore32 edi
%endmacro
global planar_page_fault_32
planar_page_fault_32:
    push dword 14
    save32 edi
    save32 esi
    save32 ebp
    sub esp, 8             ; ESP filled from the CPU return frame below
    save32 ebx
    save32 edx
    save32 ecx
    save32 eax
    mov eax, [esp + 68]     ; page-fault error
    and eax, ~3
    cmp eax, 4
    jne planar_slow32
    mov eax, [esp + 84]
    mov [esp + 32], eax     ; GPR 4 (ESP)
    mov edx, [esp + 68]
    and edx, 2
    test byte [esp + 81], 1
    jz .ready
    xor edx, edx
.ready:
    mov ebp, esp
    xor ebx, ebx
    jmp planar_common
planar_slow32:
    restore_gprs32
    jmp entry_wrapper_32

bits 64
global planar_page_fault_64
planar_page_fault_64:
    push qword 14
    push rdi
    push rsi
    push rbp
    push rsp               ; replaced with guest RSP from the CPU frame
    push rbx
    push rdx
    push rcx
    push rax
    mov eax, [rsp + 72]
    and eax, ~3
    cmp eax, 4
    jne planar_slow64
    cmp word [rsp + 88], 0x33
    je planar_slow64
    mov rax, cr2
    shr rax, 32
    jnz planar_slow64
    mov rax, [rsp + 104]
    mov [rsp + 32], rax
    mov edx, [rsp + 72]
    and edx, 2
    test byte [rsp + 97], 1
    jz .ready
    xor edx, edx
.ready:
    mov ebp, esp
    mov ebx, 1
    jmp far dword [rel call32]
%macro restore_gprs64 0
    pop rax
    pop rcx
    pop rdx
    pop rbx
    add rsp, 8
    pop rbp
    pop rsi
    pop rdi
%endmacro
planar_slow64:
    restore_gprs64
    jmp entry_wrapper_64

bits 32
planar_common:
    ; Both entries provide the same sixteen-u32 GPR array.
    ; Odd slots are native high halves, undefined on 32-bit entry.
    ; SS may be null on long-mode entry: establish the kernel stack selector.
    mov ax, 0x18
    mov ss, ax
    push ds
    push es
    push gs
    push ebx               ; native frame width: 0=dword, 1=qword
    push ebp               ; frame pointer; no canonical conversion on hits
    mov ecx, edx
    mov ebx, [ss:PLANAR_FAST_CONTEXT]
    cmp dword [ss:ebx + 40], 0
    je .timed
    rdtsc
    mov [ss:ebx + 52], eax
    mov [ss:ebx + 56], edx
.timed:
    test ecx, ecx
    jz planar_call
    fast_store
planar_call:
    cld
    mov ax, 0x18
    mov ds, ax
    mov es, ax
    mov ax, 0x91
    mov gs, ax
    mov eax, cr2
    mov ebp, [esp]
    mov ebx, [esp + 4]
    push eax
    push ebx
    push ebp
    call planar_fault
    add esp, 12
planar_return:
    push eax
    mov ebx, [ss:PLANAR_FAST_CONTEXT]
    account_fast
    pop eax
    pop ebp
    pop ebx
    pop gs
    pop es
    pop ds
    test ebx, ebx
    jnz planar_return_from_rust64
    mov edx, [esp + 32]
    mov [esp + 84], edx
    test eax, eax
    jz planar_slow32
    mov ax, 0x48
    mov ss, ax
    movzx esp, sp
    restore_gprs32
    add esp, 8
    iretd
planar_return_from_rust64:
    jmp 0x10:planar_return64

bits 64
planar_return64:
    mov edx, [rsp + 32]
    mov [rsp + 104], edx
    test eax, eax
    jz planar_slow64
    restore_gprs64
    lea rsp, [rsp + 16]
    iretq

align 8
call32: dd planar_common
        dw 0x08
