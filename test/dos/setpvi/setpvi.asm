; SETPVI.COM — set CR4.PVI from real mode (CPL=0).
; Same job as VSBHDA Tools/setpvi/SETPVI.ASM: or CR4 with bit 1 so ring-3
; CLI/STI hit VIF. Must run without JEMM/EMM386/QEMM (those are VM86 and
; MOV CR4 #GPs). HIMEMX-only is fine.
bits 16
org 100h

    push cs
    pop  ds
    mov  eax, cr4
    or   al, 2
    mov  cr4, eax
    mov  eax, cr4
    test al, 2
    jz   fail
    mov  dx, ok_msg
    mov  ah, 09h
    int  21h
    mov  ax, 4c00h
    int  21h

fail:
    mov  dx, fail_msg
    mov  ah, 09h
    int  21h
    mov  ax, 4c01h
    int  21h

ok_msg   db 'SETPVI PVI=1', 13, 10, '$'
fail_msg db 'SETPVI FAIL', 13, 10, '$'
