; A real-mode #UD during DPMI 0301h must use its IVT hook, even when
; the client has installed a protected-mode 0203h exception handler.
; Also check the PM 0203h handler still receives protected-mode faults.
bits 16
org 100h

    mov [rm_segment], cs
    ; DESQview probes Set System Date with an invalid date. DOS reports
    ; failure in AL; a generic CF/AX error falsely advertises DESQview.
    mov ax, 2b01h
    mov cx, 4445h
    mov dx, 5351h
    int 21h
    cmp al, 0ffh
    jne fail_rm

    mov ax, 3506h
    int 21h
    mov dx, rm_ud
    mov ax, 2506h
    int 21h

    mov ax, 1687h
    int 2fh
    test ax, ax
    jnz fail_rm
    mov [entry], di
    mov [entry+2], es
    test si, si
    jnz fail_rm              ; RetroOS's entry needs no host memory
    mov ax, 1               ; 32-bit DPMI client, initial CS is still D=0
    call far [entry]
    jc fail_rm
    movzx esp, sp
    mov byte [stage], '1'

    mov ax, 0203h
    mov bl, 6
    mov cx, cs
    mov edx, pm_ud
    int 31h
    jc fail_pm

    call invoke_rm
    cmp byte [rm_seen], 1
    jne fail_pm
    cmp byte [pm_seen], 0
    jne fail_pm

    mov byte [stage], '2'
    ud2
    cmp byte [pm_seen], 1
    jne fail_pm

    mov dx, pass_msg
    call emit_pm
    mov ax, 4c00h
    int 21h

invoke_rm:
    push ds
    pop es
    mov edi, rmcs
    mov ax, [rm_segment]
    mov [rmcs+44], ax        ; CS
    mov word [rmcs+42], rm_proc
    mov word [rmcs+46], 0    ; SP/SS=0 asks the host to supply a stack
    mov word [rmcs+48], 0
    xor cx, cx
    mov ax, 0301h
    int 31h
    jc fail_pm
    ret

rm_proc:
    ud2
    retf

rm_ud:
    push bp
    mov bp, sp
    add word [ss:bp+2], 2   ; faulting IP in the real-mode interrupt frame
    inc byte [cs:rm_seen]
    pop bp
    iret

pm_ud:
    inc byte [pm_seen]
    add dword [ss:esp+12], 2 ; faulting EIP in the 32-bit 0203h frame
    o32 retf

fail_pm:
    mov al, [stage]
    mov [fail_stage], al
    mov dx, fail_msg
    call emit_pm
    mov ax, 4c01h
    int 21h

emit_pm:
    ; Marshal DOS output explicitly instead of relying on PM DOS translation.
    mov [rmcs+20], dx        ; EDX low word
    mov dword [rmcs+28], 0900h
    mov ax, [rm_segment]
    mov [rmcs+36], ax        ; DS
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

fail_rm:
    mov dx, fail_msg
    mov ah, 09h
    int 21h
    mov ax, 4c01h
    int 21h

entry dd 0
rm_segment dw 0
stage db '0'
rm_seen db 0
pm_seen db 0
rmcs times 50 db 0
pass_msg db 'RMEXCEPT PASS', 13, 10, '$'
fail_msg db 'RMEXCEPT FAIL stage '
fail_stage db '0', 13, 10, '$'
