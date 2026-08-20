; HFSRECV.COM -- recover after HostFS disappears and returns.
org 0x100

    mov ax, 0x3D00
    mov dx, file_name
    int 0x21
    jc initial_fail
    mov bx, ax
    mov ah, 0x3F
    mov cx, 5
    mov dx, read_buf
    int 0x21
    jc initial_close_fail
    cmp ax, 5
    jne initial_close_fail
    mov si, read_buf
    mov di, hello_text
    mov cx, 5
    repe cmpsb
    jne initial_close_fail
    mov ah, 0x3E
    int 0x21

    mov dx, wait_msg
    call print

retry_open:
    mov ax, 0x3D00
    mov dx, file_name
    int 0x21
    jc retry_open_failed
    mov bx, ax
    mov ah, 0x3F
    mov cx, 5
    mov dx, read_buf
    int 0x21
    jc retry_read_failed
    cmp ax, 5
    jne retry_read_failed
    mov si, read_buf
    mov di, hello_text
    mov cx, 5
    repe cmpsb
    jne retry_read_failed
    mov ah, 0x3E
    int 0x21
    ; Do not accept a pre-outage success. The harness may still be stopping
    ; HostFS after WAIT; continue until one operation actually failed.
    cmp byte [outage_reported], 1
    jne retry_open

    mov dx, ok_msg
    call print
    mov ax, 0x4C00
    int 0x21

retry_open_failed:
    call report_outage
    jmp retry_open

retry_read_failed:
    mov ah, 0x3E
    int 0x21
    call report_outage
    jmp retry_open

report_outage:
    cmp byte [outage_reported], 1
    je report_outage_done
    mov byte [outage_reported], 1
    mov dx, outage_msg
    call print
report_outage_done:
    ret

initial_close_fail:
    mov ah, 0x3E
    int 0x21
initial_fail:
    mov dx, fail_msg
    call print
    mov ax, 0x4C01
    int 0x21

print:
    mov ah, 0x09
    int 0x21
    ret

file_name  db "H:\HELLO.TXT", 0
hello_text db "HELLO"
read_buf   times 5 db 0
wait_msg         db "HFS-RECOVER-WAIT", 13, 10, '$'
outage_msg       db "HFS-RECOVER-OUTAGE", 13, 10, '$'
ok_msg           db "HFS-RECOVER-OK", 13, 10, '$'
fail_msg         db "HFS-RECOVER-BAD", 13, 10, '$'
outage_reported   db 0
