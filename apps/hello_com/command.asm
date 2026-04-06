; COMMAND.COM — minimal shell for RetroOS
;
; All parsing and dispatching lives in the kernel's synth INT 31h handler:
;   AH=01h SYNTH_FORK_EXEC_WAIT: reads caller's own PSP cmdline, strips "/C",
;          fork+execs the named program, blocks until child exits or F11.
;          Out: CF=0, BX=child_pid, AX=0 exited | AX=1 decoupled
;               CF=1, AX=errno on failure.
;   AH=00h SYNTH_VGA_TAKE: adopt target pid's final screen (BX=child_pid).
;          Matches 4B00 in-process semantics: caller of 4B00 would normally
;          resume with the child's final HW state; fork_exec+wait breaks
;          that because child runs in its own thread with its own vga. The
;          take copies the child's saved vga back into our own so DN (our
;          4B00 caller) resumes from the child's farewell screen.
;
; Assemble: nasm -f bin -o COMMAND.COM command.asm
org 0x100

    mov ah, 0x01
    int 0x31
    jc .err
    test ax, ax
    jnz .bg

    ; Child exited normally — adopt its final screen, forward exit code.
    xor ah, ah              ; AH=00 SYNTH_VGA_TAKE, BX=child_pid
    int 0x31
    mov ah, 0x4D            ; DOS: get subprocess return code
    int 0x21                ; AL = child exit code
    mov ah, 0x4C
    int 0x21

.bg:
    mov ah, 0x09
    mov dx, bg_msg
    int 0x21
    mov ax, 0x4C00
    int 0x21

.err:
    mov ah, 0x09
    mov dx, err_msg
    int 0x21
    mov ax, 0x4C01
    int 0x21

bg_msg  db '[Backgrounded]', 0x0D, 0x0A, '$'
err_msg db 'Bad command or file name', 0x0D, 0x0A, '$'
