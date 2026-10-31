bits 16
segment _TEXT public class=CODE use16
extern InitTask, DOSExit, RegisterClass, CreateWindow, DefWindowProc
extern SetActiveWindow, SetFocus, GetMessage, TranslateMessage, DispatchMessage
global _start
_start:
    call far InitTask
    test ax,ax
    jz fail
    mov [wc+4],cs
    mov [wc+10],ds
    mov [wc+24],ds
    push ds
    push word wc
    call far RegisterClass
    test ax,ax
    jz fail
    push ds
    push word classname
    push ds
    push word classname
    push dword 0x10000000
    push word 0
    push word 0
    push word 200
    push word 100
    push word 0
    push word 0
    push ds
    push dword 0
    call far CreateWindow
    test ax,ax
    jz fail
    mov [hwnd],ax
    push ax
    call far SetActiveWindow
    push word [hwnd]
    call far SetFocus
    mov dx,ready
    mov ah,9
    int 0x21
.loop:
    push ds
    push word msg
    push word 0
    push word 0
    push word 0
    call far GetMessage
    test ax,ax
    jz fail
    cmp word [msg+2],0x100
    jne .char
    cmp word [msg+4],'A'
    jne .dispatch
    inc word [down]
    jmp .dispatch
.char:
    cmp word [msg+2],0x102
    jne .dispatch
    cmp word [msg+4],'a'
    jne fail
    cmp word [down],1
    jne fail
    mov ax,[hwnd]
    cmp [msg],ax
    jne fail
    mov dx,passed
    mov ah,9
    int 0x21
    mov dx,done
    mov ah,9
    int 0x21
    mov ax,0x4c00
    call far DOSExit
.dispatch:
    push ds
    push word msg
    call far TranslateMessage
    push ds
    push word msg
    call far DispatchMessage
    jmp .loop
fail:
    mov dx,failed
    mov ah,9
    int 0x21
    mov ax,0x4c01
    call far DOSExit
wndproc:
    push bp
    mov bp,sp
    push word [bp+14]
    push word [bp+12]
    push word [bp+10]
    push dword [bp+6]
    call far DefWindowProc
    pop bp
    retf 10
segment _DATA public class=DATA use16
    times 32 db 0 ; Wine InitTask instance data
wc: dw 0
    dw wndproc,0
    dw 0,0,0,0,0,0
    dd 0
    dw classname,0
hwnd dw 0
down dw 0
msg times 20 db 0
classname db 'WineKey16',0
ready db 'KEY READY',10,'$'
passed db 'KEY PASS',10,'$'
failed db 'KEY FAIL',10,'$'
done db 'RETROOS-SUITE-DONE',10,'$'
segment STACK stack class=STACK use16
    resb 8192
group DGROUP _DATA STACK
