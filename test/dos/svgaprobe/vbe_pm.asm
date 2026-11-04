; Copy and execute all three VBE 2.0 PM entry points with INT 10h hooked.
bits 16
org 100h
%macro stage 1
    mov byte [phase], %1
%endmacro
    push cs
    pop ds
    mov [rm_segment], cs
    stage '1'
    push cs
    pop es
    mov ax, 4f01h
    mov cx, 140h
    mov di, info
    int 10h
    cmp ax, 004fh
    jne rm_fail
    cmp word [info+12h], 320
    jne rm_fail
    cmp word [info+14h], 240
    jne rm_fail
    cmp byte [info+19h], 8
    jne rm_fail
    cmp word [info+6], 64
    jne rm_fail
    mov ax, 4f02h
    mov bx, 140h
    int 10h
    cmp ax, 004fh
    jne rm_fail
    mov ax, 4f06h
    xor bx, bx
    mov cx, 336
    int 10h
    cmp ax, 004fh
    jne rm_fail
    cmp bx, 336
    jne rm_fail
    stage '2'
    mov ax, 1687h
    int 2fh
    test ax, ax
    jnz rm_fail
    mov [dpmi_entry], di
    mov [dpmi_entry+2], es
    push cs
    pop es
    mov bx, 1000h
    mov ah, 4ah
    int 21h
    jc rm_fail
    test si, si
    jz .enter
    mov bx, si
    mov ah, 48h
    int 21h
    jc rm_fail
    mov es, ax
.enter:
    mov ax, 1
    call far [dpmi_entry]
    jc rm_fail
    movzx esp, sp
    stage '3'
    mov ax, 000ah
    mov bx, cs
    int 31h
    jc rm_fail
    mov [pm_entry+4], ax
    mov bx, ax
    mov ax, 0009h
    mov cx, 40fah
    int 31h
    jc rm_fail
    jmp dword far [pm_entry]
rm_fail:
    mov dx, failure
    mov ah, 9
    int 21h
    mov ax, 4c01h
    int 21h

bits 32
protected:
    stage '4'
    mov eax, 4f0ah
    xor ebx, ebx
    int 10h
    cmp ax, 004fh
    jne pm_fail
    movzx ecx, cx
    cmp ecx, 128
    ja pm_fail
    cmp ecx, 8
    jb pm_fail
    ; ES:EDI is a protected-mode pointer. Copy the table into our own CS,
    ; proving entry points do not depend on the original BIOS address.
    mov esi, edi
    push es
    pop fs
    push ds
    pop es
    mov edi, copied
    fs rep movsb
    movzx eax, word [copied]
    add eax, copied
    mov [bank_entry], eax
    movzx eax, word [copied+2]
    add eax, copied
    mov [start_entry], eax
    movzx eax, word [copied+4]
    add eax, copied
    mov [palette_entry], eax

    ; DOS extenders may hook INT 10h to translate pointers and reflect calls
    ; to real mode. PM entry points must bypass that path entirely.
    mov eax, 0204h
    mov ebx, 10h
    int 31h
    jc pm_fail
    mov [int10_original], edx
    mov [int10_original+4], cx
    mov eax, 0205h
    xor ecx, ecx
    mov cx, cs
    mov edx, int10_hook
    int 31h
    jc pm_fail

    stage '5'

    mov eax, 4f05h
    xor ebx, ebx
    mov edx, 1
    call [bank_entry]
    cmp ax, 004fh
    jne pm_fail
    mov eax, 2
    mov ebx, 0a000h
    int 31h
    jc pm_fail
    mov es, ax
    mov byte [es:0], 5ah
    xor ebx, ebx
    xor edx, edx
    call [bank_entry]
    cmp ax, 004fh
    jne pm_fail
    mov edx, 1
    call [bank_entry]
    cmp ax, 004fh
    jne pm_fail
    cmp byte [es:0], 5ah
    jne pm_fail
    cmp byte [hook_calls], 0
    jne pm_fail

%ifdef VBE_VISUAL
    ; Initialize two solid-colour pages, then exercise PM palette and page
    ; changes without any INT 10h readback that could invalidate scanout.
    xor esi, esi
.fill_bank:
    xor ebx, ebx
    mov edx, esi
    call [bank_entry]
    cmp ax, 004fh
    jne pm_fail
    xor edi, edi
    mov ecx, 65536
    mov al, 7
    cmp esi, 2
    jb .fill
    inc al
.fill:
    cld
    rep stosb
    inc esi
    cmp esi, 4
    jb .fill_bank
    push ds
    pop es
    mov eax, 4f09h
    xor ebx, ebx
    mov ecx, 2
    mov edx, 7
    mov edi, visual_palette
    int 10h
    mov eax, 4f07h
    xor ebx, ebx
    xor ecx, ecx
    xor edx, edx
    int 10h
    mov edx, visual_red
    call visual_wait

    mov eax, 4f09h
    xor ebx, ebx
    mov ecx, 1
    mov edx, 7
    mov edi, visual_green_palette
    call [palette_entry]
    cmp ax, 004fh
    jne pm_fail
    xor edx, edx ; console output would itself invalidate scanout
    call visual_wait

    mov ebx, 80h
    mov ecx, 32768 ; byte offset 131072, in dwords
    xor edx, edx
    call [start_entry]
    cmp ax, 004fh
    jne pm_fail
    xor edx, edx
    call visual_wait
    mov edx, success
    xor ebx, ebx
    jmp finish
visual_wait:
    test edx, edx
    jz .wait_key
    mov [rmcs+20], edx
    mov dword [rmcs+28], 0900h
    mov ax, [rm_segment]
    mov [rmcs+36], ax
    push ds
    pop es
    mov edi, rmcs
    xor ecx, ecx
    mov ebx, 21h
    mov eax, 0300h
    int 31h
.wait_key:
    xor eax, eax
    int 16h
    ret
visual_palette db 0,0,63,0, 63,0,0,0
visual_green_palette db 0,63,0,0
visual_red db 'VBE-VISUAL-RED',13,10,'$'
%endif

    stage '6'
    push ds
    pop es
    mov eax, 4f09h
    xor ebx, ebx
    mov ecx, 1
    mov edx, 7
    mov edi, palette
    call [palette_entry]
    cmp ax, 004fh
    jne pm_fail
    cmp byte [hook_calls], 0
    jne pm_fail
    mov eax, 4f09h
    mov ebx, 1
    mov edi, readback
    int 10h
    cmp ax, 004fh
    jne pm_fail
    cmp dword [readback], 001d1103h
    jne pm_fail
    cmp byte [hook_calls], 1
    jne pm_fail

    stage '7'
    mov byte [hook_calls], 0
    ; DX:CX holds a dword address, including a nonzero high word and x.
    mov eax, 4f07h
    xor ebx, ebx
    mov ecx, (336*1024+4)/4 & 0ffffh
    mov edx, (336*1024+4)/4 >> 16
    call [start_entry]
    cmp ax, 004fh
    jne pm_fail
    cmp byte [hook_calls], 0
    jne pm_fail
    mov eax, 4f07h
    mov ebx, 1
    int 10h
    cmp ax, 004fh
    jne pm_fail
    cmp cx, 4
    jne pm_fail
    cmp dx, 1024
    jne pm_fail
    cmp byte [hook_calls], 1
    jne pm_fail
    mov edx, success
    mov ebx, 0
    jmp finish
pm_fail:
    mov edx, failure
    mov ebx, 1
finish:
    push ebx
    mov [rmcs+20], edx
    mov dword [rmcs+28], 0900h
    mov ax, [rm_segment]
    mov [rmcs+36], ax
    push ds
    pop es
    mov edi, rmcs
    xor ecx, ecx
    mov ebx, 21h
    mov eax, 0300h
    int 31h
    pop eax
    or eax, 4c00h
    int 21h
int10_hook:
    inc byte [hook_calls]
    jmp far [int10_original]
int10_original dd 0
               dw 0
hook_calls db 0
dpmi_entry dw 0, 0
pm_entry dd protected
         dw 0
bank_entry dd 0
start_entry dd 0
palette_entry dd 0
palette db 3,17,29,0
rm_segment dw 0
rmcs times 50 db 0
readback dd 0
info times 256 db 0
copied times 128 db 0
success db 'VBE-PM PASS',13,10,'$'
failure db 'VBE-PM FAIL stage '
phase db '1',13,10,'$'
