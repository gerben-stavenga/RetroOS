; A default hardware IRQ must protect PM registers from a legacy RM ISR.
; Software INT reflection must still return the RM handler's register results.
bits 16
org 100h
%macro seed_registers 0
    mov eax, 11223344h
    mov ebx, 55667788h
    mov ecx, 99aabbcch
    mov edx, 0ddeeff00h
    mov esi, 12345678h
    mov edi, 87654321h
    mov ebp, 5a5a0018h
%endmacro

%macro check_registers 1
    cmp eax, 11223344h
    jne %1
    cmp ebx, 55667788h
    jne %1
    cmp ecx, 99aabbcch
    jne %1
    cmp edx, 0ddeeff00h
    jne %1
    cmp esi, 12345678h
    jne %1
    cmp edi, 87654321h
    jne %1
    cmp ebp, 5a5a0018h
    jne %1
%endmacro

    cli
    mov [rm_segment], cs
    mov dx, rm_timer
    mov ax, 2508h
    int 21h
    mov dx, rm_software
    mov ax, 2560h
    int 21h
    mov ax, 1687h
    int 2fh
    test ax, ax
    jnz fail_rm
    mov [entry], di
    mov [entry+2], es
    mov ax, 1
    call far [entry]
    jc fail_rm
    movzx esp, sp
    cli
    int 60h
    cmp eax, 89abcdefh
    jne fail_pm
    mov byte [seen], 0
    mov [client_ss], ss
    mov [client_sp], esp
    seed_registers
    sti
.wait:
    cmp byte [seen], 0
    je .wait
    cli
    check_registers fail_pm
    cmp esp, [client_sp]
    jne fail_pm
    mov ax, ss
    cmp ax, [client_ss]
    jne fail_pm
    ; A fault handler is already on the locked PM stack. Exercise an
    ; unhooked IRQ nested on that live stack as well as the first-entry case.
    mov ax, 0203h
    mov bl, 6
    mov cx, cs
    mov edx, pm_exception
    int 31h
    jc fail_pm
    mov byte [seen], 0
    ud2
    cmp byte [failed], 0
    jne fail_pm
    mov dx, pass_msg
    call emit
    mov ax, 4c00h
    int 21h
pm_exception:
    pushad
    seed_registers
    sti
.wait:
    cmp byte [seen], 0
    je .wait
    cli
    check_registers .failed
    jmp .done
.failed:
    mov byte [failed], 1
.done:
    popad
    add dword [ss:esp+12], 2
    o32 retf

rm_timer:
    pusha
    ; A 16-bit DOS ISR saves AX etc, but uses 32-bit ops for fast buffer work.
    mov eax, 80808080h
    mov ebx, 11112222h
    mov ecx, 33334444h
    mov edx, 55556666h
    mov esi, 77778888h
    mov edi, 9999aaaah
    mov ebp, 0bbbbcccch
    inc byte [cs:seen]
    mov al, 20h
    out 20h, al
    popa
    iret
rm_software:
    mov eax, 89abcdefh
    iret
emit:
    mov [rmcs+20], dx
    mov dword [rmcs+28], 0900h
    mov ax, [rm_segment]
    mov [rmcs+36], ax
    push ds
    pop es
    mov edi, rmcs
    xor cx, cx
    mov bx, 21h
    mov ax, 0300h
    int 31h
    ret
fail_pm:
    mov dx, fail_msg
    call emit
    mov ax, 4c01h
    int 21h
fail_rm:
    mov dx, fail_msg
    mov ah, 9
    int 21h
    mov ax, 4c01h
    int 21h
entry dd 0
rm_segment dw 0
client_ss dw 0
client_sp dd 0
seen db 0
failed db 0
rmcs times 50 db 0
pass_msg db 'IRQ-REGS PASS', 13, 10, '$'
fail_msg db 'IRQ-REGS FAIL', 13, 10, '$'
