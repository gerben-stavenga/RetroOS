; VIFIRET.COM — ring-3 DPMI IRETD must not load VIF.
;
; RetroOS DPMI clients run at CPL 3 with real IOPL=1. Spec-strict mode
; (vIOPL=1) also sets CR4.PVI, so VIF is a hardware flag. The SDM's
; IRETD at CPL>0 does not load VIF/VIP from the frame; 86Box used to
; copy the whole high EFLAGS word (pmodeiret is32 path) and Dark Forces
; hung with VIF=0. That path is a 32-bit CS IRET, so this probe builds a
; 32-bit code selector and IRETDs from there — a 66h-prefixed IRET in a
; 16-bit CS is not the same instruction on every emulator.
;
; This program:
;   1. Unless `/H` is on the command line, pins RetroOS spec-strict mode
;      (INT 31h AH=09 CL=1) so --cmd launches still get PVI.
;      `/H` means an external host (HDPMI32I + SETPVI) already set CR4.PVI;
;      do not call that RetroOS-only real-mode INT 31h.
;   2. Enters 32-bit DPMI (INT 2Fh AX=1687h, AX=1 on the mode switch).
;      HDPMI32I rejects 16-bit clients. SS.B=1, so ESP is zero-extended
;      from SP or a 32-bit push/IRETD #SS.
;   3. Makes a 32-bit CS alias, far-jumps, IRETDs a frame with VIF=VM=IF
;      cleared, then returns to 16-bit CS to print. PM INT 21h goes
;      through DPMI AX=0300h so both RetroOS and HDPMI can write the log.
;   4. RetroOS: DPMI AX=0902h must stay 1; if PUSHFD showed hardware VIF,
;      it must still be set. `/H`: hardware VIF (PUSHFD bit 19) is required
;      both before and after — HDPMI's 0902h does not track CR4.PVI.
;
; Prints "VIFIRET PASS" or "VIFIRET FAIL stage N", and writes the same
; line to C:\VIFIRET.LOG so a GUI backend (86Box) can be judged from
; the disk image.
bits 16
org 100h

VIF_FLAG equ (1 << 19)
AC_FLAG  equ (1 << 18)
VM_FLAG  equ (1 << 17)
NT_FLAG  equ (1 << 14)
IF_FLAG  equ (1 << 9)
TF_FLAG  equ (1 << 8)

start:
    push cs
    pop  ds
    mov  [rm_ds], cs
    mov  ah, 3Ch
    xor  cx, cx
    mov  dx, fname
    int  21h
    jc   .nolog
    mov  [fhandle], ax
.nolog:
    xor  ax, ax
    mov  [hdpmimode], al
    mov  si, 81h
.scan:
    lodsb
    cmp  al, 0Dh
    je   .scandone
    cmp  al, 'H'
    je   .got_h
    cmp  al, 'h'
    je   .got_h
    jmp  .scan
.got_h:
    mov  byte [hdpmimode], 1
    jmp  .scan
.scandone:

    mov  byte [stage], '1'
    cmp  byte [hdpmimode], 0
    jne  .skip_synth
    ; Spec-strict vIOPL=1 enables hardware PVI on this thread (RetroOS).
    mov  ax, 0900h
    mov  cl, 1
    int  31h
.skip_synth:

    mov  byte [stage], '2'
    mov  ax, 1687h
    int  2fh
    test ax, ax
    jz   .dpmi_ok
    mov  [dpmi_ax], ax
    jmp  fail
.dpmi_ok:
    mov  [entry_off], di
    mov  [entry_seg], es
    mov  [dpmi_si], si

    ; A .COM owns all remaining conventional memory; AH=48h cannot
    ; succeed until we shrink (INT 21h AH=4Ah).
    ; AH=4Ah resizes ES, not CS. 1687h left ES on the host entry stub.
    push cs
    pop  es
    mov  bx, 512
    mov  ah, 4Ah
    int  21h

    test si, si
    jz   do_switch
    mov  bx, si
    mov  ah, 48h
    int  21h
    jnc  .gotmem
    mov  [dpmi_ax], ax
    mov  byte [stage], 'm'
    jmp  fail
.gotmem:
    mov  es, ax
do_switch:
    mov  ax, 1                  ; 32-bit client
    call far [entry_off]
    jnc  .entered
    mov  byte [stage], 'e'
    jmp  fail
.entered:
    mov  byte [in_pm], 1
    movzx esp, sp
    and  esp, 0xfffffffc

    mov  byte [stage], '3'
    mov  ax, cs
    and  al, 3
    cmp  al, 3
    jne  fail
    mov  [sel16], cs

    ; 32-bit CS with the same base/limit as the 16-bit client CS.
    mov  byte [stage], 'a'
    mov  ax, 0000h
    mov  cx, 1
    int  31h
    jc   fail
    mov  [sel32], ax

    mov  ax, 0006h
    mov  bx, cs
    int  31h
    jc   fail
    mov  ax, 0007h
    mov  bx, [sel32]
    int  31h
    jc   fail

    mov  ax, 0008h
    mov  bx, [sel32]
    xor  cx, cx
    mov  dx, 0xffff
    int  31h
    jc   fail

    mov  ax, 0009h
    mov  bx, [sel32]
    mov  cx, 40FBh              ; 32-bit present DPL-3 readable code
    int  31h
    jc   fail
    or   word [sel32], 3        ; RPL=CPL on the IRETD CS
    lar  eax, [sel32]
    jnz  fail                   ; ZF=1 if LAR succeeded
    test eax, 1 << 22           ; D=1, else 32-bit ops run as 16-bit
    jz   fail

    sti
    mov  byte [stage], '4'
    cmp  byte [hdpmimode], 0
    jne  .skip0902
    mov  ax, 0902h
    int  31h
    test al, al
    jz   fail
.skip0902:
    pushfd
    pop  eax
    mov  [live_flags], eax

    ; IRETD from a 32-bit CS — 86Box's pmodeiret(is32) path.
    push word [sel32]
    push word pm32
    retf

bits 32
pm32:
    movzx esp, sp
    and  esp, 0xfffffffc
    mov  eax, [live_flags]
    and  eax, ~(VIF_FLAG | VM_FLAG | IF_FLAG | NT_FLAG | AC_FLAG | TF_FLAG)
    or   eax, 2
    push eax
    movzx eax, word [sel32]
    push eax
    push after_iret
    iretd

after_iret:
    movzx eax, word [sel16]
    push eax
    push check16
    retf

bits 16
check16:
    cmp  byte [hdpmimode], 0
    je   .dpmi_vif
    ; HDPMI+SETPVI: judge hardware VIF only.
    mov  byte [stage], 'p'
    test dword [live_flags], VIF_FLAG
    jz   fail
    mov  byte [stage], '6'
    pushfd
    pop  eax
    test eax, VIF_FLAG
    jz   fail
    jmp  pass

.dpmi_vif:
    mov  byte [stage], '5'
    mov  ax, 0902h
    int  31h
    test al, al
    jz   fail

    mov  byte [stage], '6'
    pushfd
    pop  eax
    test dword [live_flags], VIF_FLAG
    jz   pass
    test eax, VIF_FLAG
    jz   fail

pass:
    mov  dx, pass_msg
    call emit
    mov  al, 0
    jmp  exit

fail:
    mov  al, [stage]
    mov  [fail_stage_char], al
    mov  dx, fail_msg
    call emit
    mov  ax, [dpmi_ax]
    call puthex
    mov  dl, ' '
    mov  ah, 02h
    call dos21
    mov  ax, [dpmi_si]
    call puthex
    mov  dx, newline
    call emit
    mov  al, 1

exit:
    mov  ah, 4Ch
    mov  bx, [fhandle]
    cmp  bx, 0xFFFF
    je   .noclose
    push ax
    mov  ah, 3Eh
    call dos21
    pop  ax
.noclose:
    call dos21

emit:
    push ax
    push bx
    push cx
    push dx
    push si
    mov  ah, 09h
    call dos21
    mov  bx, [fhandle]
    cmp  bx, 0xFFFF
    je   .done
    mov  si, dx
    xor  cx, cx
.len:
    lodsb
    cmp  al, '$'
    je   .write
    inc  cx
    jmp  .len
.write:
    mov  ah, 40h
    call dos21
.done:
    pop  si
    pop  dx
    pop  cx
    pop  bx
    pop  ax
    ret

puthex:
    push ax
    mov  cx, 4
.hex:
    rol  ax, 4
    push ax
    and  al, 0Fh
    add  al, '0'
    cmp  al, '9'
    jbe  .dig
    add  al, 7
.dig:
    mov  dl, al
    mov  ah, 02h
    call dos21
    pop  ax
    loop .hex
    pop  ax
    ret

; INT 21h in RM; DPMI 0300h once we are a 32-bit PM client (no PMDOS).
dos21:
    cmp  byte [in_pm], 0
    jne  sim21
    int  21h
    ret

sim21:
    push eax
    push ebx
    push ecx
    push edx
    push esi
    push edi
    push es
    mov  dword [rmcs+1Ch], eax
    mov  dword [rmcs+10h], ebx
    mov  dword [rmcs+18h], ecx
    mov  dword [rmcs+14h], edx
    mov  ax, [rm_ds]
    mov  [rmcs+24h], ax
    xor  ax, ax
    mov  [rmcs+2Eh], ax
    mov  [rmcs+30h], ax
    pushfd
    pop  eax
    mov  [rmcs+20h], ax
    push ds
    pop  es
    mov  di, rmcs
    movzx edi, di
    mov  ax, 0300h
    mov  bx, 21h
    xor  cx, cx
    int  31h
    pop  es
    pop  edi
    pop  esi
    pop  edx
    pop  ecx
    pop  ebx
    pop  eax
    ret

entry_off   dw 0
entry_seg   dw 0
sel16       dw 0
sel32       dw 0
dpmi_ax     dw 0
dpmi_si     dw 0
live_flags  dd 0
hdpmimode   db 0
in_pm       db 0
rm_ds       dw 0
rmcs        times 50 db 0
stage       db '?'
fhandle     dw 0xFFFF
fname       db 'VIFIRET.LOG', 0
pass_msg    db 'VIFIRET PASS', 13, 10, '$'
fail_msg    db 'VIFIRET FAIL stage '
fail_stage_char db '?'
            db ' AX/SI=', '$'
newline     db 13, 10, '$'
