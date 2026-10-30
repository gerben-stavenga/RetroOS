bits 16
segment _TEXT public class=CODE use16
extern LoadCursor, DestroyCursor
extern Debug, Exit, timeSetEvent, timeKillEvent, timeGetTime, CallWindowProc
global _start
_start:
    mov [initial_sp],sp
    push word 0
    push dword 32512
    call far LoadCursor
    test ax,ax
    jz fail
    push ax
    call far DestroyCursor
    test ax,ax
    jz fail
    push word 30
    push word 1
    push cs
    push word timer
    push dword 0x12345678
    push word 0x101
    call far timeSetEvent
    test ax,ax
    jz fail
    mov [timer_id],ax
    ; Leave a window callback suspended while the timer enters NE on its own
    ; stack and recursively calls USER. The two bridge frames must not alias.
    push cs
    push word wait_callback
    push word 0
    push word 0
    push word 0
    push dword 0
    call far CallWindowProc
    cmp ax,0x1234
    jne fail
    call wait_a_bit
    cmp word [calls],3
    jne fail
    push word [timer_id]
    call far timeKillEvent
    cmp ax,11
    jne fail
    push word 5
    push word 0
    push cs
    push word timer
    push dword 0x12345678
    push word 0
    call far timeSetEvent
    test ax,ax
    jz fail
    call wait_a_bit
    cmp word [calls],4
    jne fail
    cmp sp,[initial_sp]
    jne fail
    push ds
    push word passed
    call far Debug
    push word 0
    call far Exit
fail:
    push ds
    push word failed
    call far Debug
    push word 1
    call far Exit
wait_a_bit:
    call far timeGetTime
    mov [started],ax
.loop:
    call far timeGetTime
    sub ax,[started]
    cmp ax,100
    jb .loop
    ret
wait_callback:
    ; No API gate or message pump while waiting for the first hardware tick.
.spin:
    cmp word [calls],0
    je .spin
    call far timeGetTime
    mov [started],ax
.loop:
    cmp word [calls],3
    jae .done
    call far timeGetTime
    sub ax,[started]
    cmp ax,3000
    ja fail
    jmp .loop
.done:
    mov ax,0x1234
    xor dx,dx
    retf 10
timer:
    push bp
    mov bp,sp
    mov ax,ds
    mov dx,seg calls
    cmp ax,dx
    jne fail
    cmp dword [ss:bp+14],0x12345678
    jne fail
    cmp word [ss:bp+18],0
    jne fail
    cmp dword [ss:bp+6],0
    jne fail
    cmp dword [ss:bp+10],0
    jne fail
    cmp word [ss:bp+20],0
    je fail
    push cs
    push word nested
    push word 0
    push word 0
    push word 0
    push dword 0
    call far CallWindowProc
    cmp ax,0x5678
    jne fail
    inc word [calls]
    cmp word [calls],3
    jne .done
    push word [ss:bp+20]
    call far timeKillEvent
    test ax,ax
    jnz fail
.done:
    pop bp
    retf 16
nested:
    mov ax,0x5678
    xor dx,dx
    retf 10
segment _DATA public class=DATA use16
initial_sp dw 0
calls dw 0
timer_id dw 0
started dw 0
passed db 'WIN16 MULTIMEDIA PASS',0
failed db 'WIN16 MULTIMEDIA FAIL',0
segment STACK stack class=STACK use16
    resb 8192
group DGROUP _DATA STACK
