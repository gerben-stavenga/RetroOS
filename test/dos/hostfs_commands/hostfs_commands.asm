; HFSOPS.COM -- successful HostFS command probe.
;
; Exercise DOS paths that reach HostFS MKDIR and directory STAT/lookup.
org 0x100

    ; AH=39h: create a directory through HostFS MKDIR.
    mov ah, 0x39
    mov dx, dir_name
    int 0x21
    jc .fail

    ; AH=3Bh: change into it; directory resolution uses HostFS STAT.
    mov ah, 0x3B
    mov dx, dir_name
    int 0x21
    jc .fail

    mov dx, ok_msg
    mov ah, 0x09
    int 0x21
    mov ax, 0x4C00
    int 0x21

.fail:
    mov dx, fail_msg
    mov ah, 0x09
    int 0x21
    mov ax, 0x4C01
    int 0x21

dir_name db "H:\HFSOPS", 0
ok_msg   db "HFSOPS-OK", 13, 10, '$'
fail_msg db "HFSOPS-BAD", 13, 10, '$'
