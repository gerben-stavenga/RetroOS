; HFS_PROBE.COM -- one successful HostFS read.
org 0x100

    mov ax, 0x3D00
    mov dx, file_name
    int 0x21
    jc .fail
    mov bx, ax
    mov ah, 0x3F
    mov cx, 5
    mov dx, read_buf
    int 0x21
    jc .fail_close
    cmp ax, 5
    jne .fail_close
    mov si, read_buf
    mov di, hello_text
    mov cx, 5
    repe cmpsb
    jne .fail_close
    mov ah, 0x3E
    int 0x21

    mov dx, ok_msg
    call print
    mov ax, 0x4C00
    int 0x21

.fail_close:
    mov ah, 0x3E
    int 0x21
.fail:
    mov dx, fail_msg
    call print
    mov ax, 0x4C01
    int 0x21

print:
    mov ah, 0x09
    int 0x21
    ret

file_name db "H:\HELLO.TXT", 0
hello_text db "HELLO"
read_buf   times 5 db 0
ok_msg     db "HFS-PROBE-OK", 13, 10, '$'
fail_msg   db "HFS-PROBE-BAD", 13, 10, '$'
