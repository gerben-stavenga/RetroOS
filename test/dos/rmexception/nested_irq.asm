; Active PM handlers retain their switched stack across nested RM calls.
; Raw PM code inside an RM call must not activate a suspended PM stack.
bits 16
org 100h
    mov [rm_segment], cs
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
    mov [data_sel], ds
    mov ax, 000ah
    mov bx, ds
    int 31h
    jc fail_pm
    mov [stack_sel], ax
    mov bx, ax
    mov ax, 0009h
    mov cx, 40f3h
    int 31h
    jc fail_pm
    mov ax, 0204h
    mov bl, 8
    int 31h
    mov [old_sel], cx
    mov [old_off], edx
    mov ax, 0205h
    mov cx, cs
    mov edx, timer
    int 31h
    jc fail_pm
    mov [client_ss], ss
    mov [client_sp], esp
    mov ax, ds
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov eax, 11223344h
    mov ebx, 55667788h
    mov ecx, 99aabbcch
    mov edx, 0ddeeff00h
    mov esi, 12345678h
    mov edi, 87654321h
    mov ebp, 5a5a0018h
    sti
.wait:
    cmp byte [outer_done], 0
    je .wait
    cli
    cmp eax, 11223344h
    jne fail_pm
    cmp ebx, 55667788h
    jne fail_pm
    cmp ecx, 99aabbcch
    jne fail_pm
    cmp edx, 0ddeeff00h
    jne fail_pm
    cmp esi, 12345678h
    jne fail_pm
    cmp edi, 87654321h
    jne fail_pm
    cmp ebp, 5a5a0018h
    jne fail_pm
    cmp esp, [client_sp]
    jne fail_pm
    mov ax, ss
    cmp ax, [client_ss]
    jne fail_pm
    mov ax, es
    cmp ax, [data_sel]
    jne fail_pm
    mov ax, fs
    cmp ax, [data_sel]
    jne fail_pm
    mov ax, gs
    cmp ax, [data_sel]
    jne fail_pm
    ; Repeat from an RM call with no PM handler active. A raw round trip
    ; through a private PM stack must not make it the next IRQ's stack.
    mov ax, 0306h
    int 31h
    jc fail_pm
    mov [rm_to_pm], cx
    mov [rm_to_pm+2], bx
    mov [pm_to_rm], edi
    mov [pm_to_rm+4], si
    mov [pm_code], cs
    mov dword [private_stack_end-12], 11223344h
    mov dword [private_stack_end-8], 55667788h
    mov dword [private_stack_end-4], 99aabbcch
    mov byte [phase], 2
    push ds
    pop es
    mov ax, [rm_segment]
    mov [rmcs+44], ax
    mov word [rmcs+42], rm_raw
    ; Keep IRQs off until the raw round trip has completed.
    mov word [rmcs+32], 0002h
    mov edi, rmcs
    xor cx, cx
    mov ax, 0301h
    int 31h
    jc fail_pm
    cmp dword [private_stack_end-12], 11223344h
    jne fail_pm
    cmp dword [private_stack_end-8], 55667788h
    jne fail_pm
    cmp dword [private_stack_end-4], 99aabbcch
    jne fail_pm
    mov ax, 0205h
    mov bl, 8
    mov cx, [old_sel]
    mov edx, [old_off]
    int 31h
    cmp byte [failed], 0
    jne fail_pm
    mov dx, pass_msg
    call emit
    mov ax, 4c00h
    int 21h

timer:
    push ds
    push ax
    mov ax, [cs:data_sel]
    mov ds, ax
    pop ax
    cmp byte [phase], 2
    je raw_nested
    cmp byte [depth], 0
    jne nested
    pushad
    push es
    mov [outer_ss], ss
    mov [outer_sp], esp
    mov ax, [stack_sel]
    mov ss, ax
    mov esp, private_stack_end
    mov ax, [cs:data_sel]
    mov ds, ax
    mov es, ax
    mov byte [depth], 1
    mov al, 20h
    out 20h, al
    mov ax, [rm_segment]
    mov [rmcs+44], ax
    mov word [rmcs+42], rm_wait
    mov word [rmcs+32], 0202h
    mov edi, rmcs
    xor cx, cx
    mov ax, 0301h
    int 31h
    mov byte [outer_done], 1
    mov ax, [outer_ss]
    mov ebx, [outer_sp]
    mov ss, ax
    mov esp, ebx
    pop es
    popad
    pop ds
    o32 iret
nested:
    push ax
    mov ax, ss
    cmp ax, [stack_sel]
    je .correct
    mov byte [failed], 1
.correct:
    mov byte [nested_seen], 1
    mov al, 20h
    out 20h, al
    pop ax
    pop ds
    o32 iret
raw_nested:
    push ax
    mov ax, ss
    cmp ax, [outer_ss]
    je .correct
    mov byte [failed], 1
.correct:
    mov byte [raw_seen], 1
    mov al, 20h
    out 20h, al
    pop ax
    pop ds
    o32 iret

rm_raw:
    cli
    mov [cs:raw_rm_ss], ss
    mov [cs:raw_rm_sp], sp
    mov ax, [cs:data_sel]
    mov cx, ax
    mov dx, [cs:stack_sel]
    mov ebx, private_stack_end
    mov si, [cs:pm_code]
    mov edi, raw_pm
    call far [cs:rm_to_pm]
raw_pm:
    mov ax, [rm_segment]
    mov cx, ax
    mov dx, [raw_rm_ss]
    mov bx, [raw_rm_sp]
    mov si, ax
    mov di, rm_after_raw
    jmp far dword [pm_to_rm]
rm_after_raw:
    sti
.wait:
    cmp byte [cs:raw_seen], 0
    je .wait
    retf

rm_wait:
    sti
.wait:
    cmp byte [cs:nested_seen], 0
    je .wait
    retf
emit:
    mov [rmcs+20], dx
    mov dword [rmcs+28], 0900h
    mov ax, [rm_segment]
    mov [rmcs+36], ax
    mov word [rmcs+46], 0
    mov word [rmcs+48], 0
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
data_sel dw 0
stack_sel dw 0
old_sel dw 0
old_off dd 0
outer_ss dw 0
outer_sp dd 0
client_ss dw 0
client_sp dd 0
rm_to_pm dd 0
pm_to_rm dd 0
    dw 0
pm_code dw 0
raw_rm_ss dw 0
raw_rm_sp dw 0
phase db 0
raw_seen db 0
depth db 0
nested_seen db 0
outer_done db 0
failed db 0
rmcs times 50 db 0
pass_msg db 'NESTED-IRQ PASS', 13, 10, '$'
fail_msg db 'NESTED-IRQ FAIL', 13, 10, '$'
align 16
private_stack times 1024 db 0
private_stack_end:
