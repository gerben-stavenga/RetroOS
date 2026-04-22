; CWSDOOM.COM — in-process wrapper: EXEC CWSDPMI.EXE -p then EXEC DOOMS\DOOM.EXE
; Avoids COMMAND.COM's fork semantics so CWSDPMI's TSR persists into DOOM.

bits 16
org 0x100

start:
    ; Shrink our memory block so EXEC has room for the child.
    mov  ax, cs
    mov  es, ax
    mov  bx, 0x400           ; 16 KB resident
    mov  ah, 0x4A
    int  0x21
    jc   fail_shrink

    ; Patch segment fields (tail seg, FCB1 seg, FCB2 seg) in both param blocks.
    mov  ax, cs
    mov  [paramblk_cws + 4],  ax
    mov  [paramblk_cws + 8],  ax
    mov  [paramblk_cws + 12], ax
    mov  [paramblk_doom + 4],  ax
    mov  [paramblk_doom + 8],  ax
    mov  [paramblk_doom + 12], ax

    mov  ah, 0x09
    mov  dx, msg_start
    int  0x21

    ; EXEC CWSDPMI.EXE with " -p" (persistent TSR)
    mov  dx, path_cws
    mov  bx, paramblk_cws
    mov  ax, 0x4B00
    int  0x21
    jc   fail_exec1

    push cs
    pop  ds
    push cs
    pop  es

    mov  ah, 0x09
    mov  dx, msg_after_cws
    int  0x21

    ; EXEC DOOM
    mov  dx, path_doom
    mov  bx, paramblk_doom
    mov  ax, 0x4B00
    int  0x21
    jc   fail_exec2

    push cs
    pop  ds

    mov  ah, 0x09
    mov  dx, msg_done
    int  0x21
    mov  ax, 0x4C00
    int  0x21

fail_shrink:
    mov  dx, msg_shrink
    jmp  print_exit
fail_exec1:
    push cs
    pop  ds
    mov  dx, msg_fail1
    jmp  print_exit
fail_exec2:
    push cs
    pop  ds
    mov  dx, msg_fail2
print_exit:
    mov  ah, 0x09
    int  0x21
    mov  ax, 0x4C01
    int  0x21

path_cws    db 'CWSDPMI.EXE', 0
path_doom   db 'DOOMS\DOOM.EXE', 0

tail_cws    db 3, ' -p', 0x0D
tail_doom   db 0, 0x0D

; EXEC param block (AL=00): env_seg, tail(off,seg), fcb1(off,seg), fcb2(off,seg)
paramblk_cws:
    dw 0
    dw tail_cws, 0
    dw 0x5C, 0
    dw 0x6C, 0

paramblk_doom:
    dw 0
    dw tail_doom, 0
    dw 0x5C, 0
    dw 0x6C, 0

msg_start     db 'CWSDOOM: starting', 0x0D, 0x0A, '$'
msg_after_cws db 'CWSDOOM: CWSDPMI installed, launching DOOM', 0x0D, 0x0A, '$'
msg_done      db 'CWSDOOM: DOOM exited', 0x0D, 0x0A, '$'
msg_shrink    db 'CWSDOOM: shrink failed', 0x0D, 0x0A, '$'
msg_fail1     db 'CWSDOOM: CWSDPMI EXEC failed', 0x0D, 0x0A, '$'
msg_fail2     db 'CWSDOOM: DOOM EXEC failed', 0x0D, 0x0A, '$'
