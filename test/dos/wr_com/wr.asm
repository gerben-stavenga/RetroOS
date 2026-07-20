; WR.COM -- create a file, write to it, close it, and report what happened.
;
; The DOS personality is the only one that calls `vfs::create`, so this is the
; only way to exercise the ext4 WRITE path end to end (Linux open(O_CREAT) is
; not wired). Pair it with a host-side `debugfs` check of the same image to
; confirm the bytes actually reached the disk rather than a cache.
;
; Writes C:\WRTEST.TXT. Exit code 0 on success, 1 on any failed step, so a
; harness can gate on it without parsing the text.
; Assemble: nasm -f bin -o WR.COM wr.asm
org 0x100

    mov ah, 0x3C          ; DOS create-file (truncate if present)
    xor cx, cx            ; normal attributes
    mov dx, fname
    int 0x21
    jc  .fail_create
    mov bx, ax            ; keep the handle

    mov ah, 0x40          ; DOS write to handle
    mov cx, datalen
    mov dx, data
    int 0x21
    jc  .fail_write
    cmp ax, datalen       ; a short write is a failure too
    jne .fail_write

    mov ah, 0x3E          ; DOS close (flushes)
    int 0x21
    jc  .fail_close

    mov dx, msg_ok
    jmp .done_ok

.fail_create:
    mov dx, msg_create
    jmp .done_fail
.fail_write:
    mov ah, 0x3E          ; close the handle we did open
    int 0x21
    mov dx, msg_write
    jmp .done_fail
.fail_close:
    mov dx, msg_close
    jmp .done_fail

.done_ok:
    mov ah, 0x09
    int 0x21
    mov ax, 0x4C00        ; exit 0
    int 0x21
.done_fail:
    mov ah, 0x09
    int 0x21
    mov ax, 0x4C01        ; exit 1
    int 0x21

fname   db "WRTEST.TXT", 0
data    db "RetroOS ext4 write test", 13, 10
datalen equ $ - data
msg_ok     db "WR: ok", 13, 10, '$'
msg_create db "WR: create failed", 13, 10, '$'
msg_write  db "WR: write failed", 13, 10, '$'
msg_close  db "WR: close failed", 13, 10, '$'
