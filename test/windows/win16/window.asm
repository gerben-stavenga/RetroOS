bits 16
segment _TEXT public class=CODE use16
extern Exit, Debug, RegisterClass, CreateWindow, DestroyWindow, DefWindowProc
extern SendMessage, UpdateWindow, BeginPaint, EndPaint, GetClientRect
extern PostMessage, GetMessage, DispatchMessage, FillRect, CreateSolidBrush, GetPixel, GetDC, ReleaseDC
extern CreateDC, CreateBitmap, SelectObject, DeleteDC, DeleteObject, SetPixel
extern DOSExit, CreateDialog, SetDlgItemInt, GetDlgItemInt
global _start
_start:
    mov [initial_sp], sp
    ; Cross the old synthetic DC value (0x200); real contexts must keep working.
    mov word [remaining], 260
.gdi:
    push word 0
    call far CreateDC
    mov [dc], ax
    push ax
    push word 1
    push word 1
    call far CreateBitmap
    mov [bitmap], ax
    push word [dc]
    push ax
    call far SelectObject
    mov [old_bitmap], ax
    push word [dc]
    push word 0
    push word 0
    push dword 0x00113322
    call far SetPixel
    push word [dc]
    push word 0
    push word 0
    call far GetPixel
    cmp ax, 0x3322
    jne fail
    cmp dx, 0x0011
    jne fail
    push word [dc]
    push word [old_bitmap]
    call far SelectObject
    push word [bitmap]
    call far DeleteObject
    push word [dc]
    call far DeleteDC
    dec word [remaining]
    jnz .gdi
    mov [wc+4], cs
    mov [wc+10], ds
    mov [wc+24], ds
    push ds
    push word wc
    call far RegisterClass
    test ax, ax
    jz fail
    push ds
    push word classname
    push ds
    push word title
    push dword 0x10cf0000
    push word 10
    push word 10
    push word 160
    push word 120
    push word 0
    push word 0
    push ds
    push dword 0x12345678
    call far CreateWindow
    test ax, ax
    jz fail
    mov [hwnd], ax
    cmp word [created], 1
    jne fail
    cmp word [nested], 1
    jne fail
    push ax
    call far UpdateWindow
    cmp word [painted], 1
    jb fail
    push word [hwnd]
    push word 0x401
    push word 0x4321
    push dword 0x87654321
    call far PostMessage
    push ds
    push word msg
    push word [hwnd]
    push word 0x401
    push word 0x401
    call far GetMessage
    cmp ax, 1
    jne fail
    push ds
    push word msg
    call far DispatchMessage
    cmp ax, 0x1234
    jne fail
    cmp dx, 0x5678
    jne fail
    push word [hwnd]
    call far GetDC
    mov [dc], ax
    push ax
    push word 4
    push word 4
    call far GetPixel
    cmp ax, 0x3322
    jne fail
    cmp dx, 0x0011
    jne fail
    push word [hwnd]
    push word [dc]
    call far ReleaseDC
    push ds
    push ds
    push word dlg_template
    push word [hwnd]
    push cs
    push word dlgproc
    push dword 0xdeadbeef
    call far CreateDialog
    test ax, ax
    jz fail
    mov [dialog], ax
    push ax
    push word 100
    push ds
    push word translated
    push word 0
    call far GetDlgItemInt
    cmp ax, 1234
    jne fail
    cmp word [translated], 1
    jne fail
    push word [dialog]
    call far DestroyWindow
    push word [hwnd]
    call far DestroyWindow
    cmp word [destroyed], 1
    jne fail
    cmp sp, [initial_sp]
    jne fail
    push ds
    push word passed
    call far Debug
    mov ax, 0x4c00
    call far DOSExit
fail:
    push ds
    push word failed
    call far Debug
    push word 1
    call far Exit
wndproc:
    push bp
    mov bp, sp
    cmp word [bp+12], 0x81
    je .nc
    cmp word [bp+12], 1
    je .create
    cmp word [bp+12], 2
    je .destroy
    cmp word [bp+12], 0xf
    je .paint
    cmp word [bp+12], 0x400
    je .nested
    cmp word [bp+12], 0x401
    je .posted
    push word [bp+14]
    push word [bp+12]
    push word [bp+10]
    push dword [bp+6]
    call far DefWindowProc
    jmp .return
.nc:
    les bx, [bp+6]
    cmp dword [es:bx], 0x12345678
    jne fail
    cmp word [es:bx+12], 160
    jne fail
    mov ax, 1
    xor dx, dx
    jmp .return
.create:
    inc word [created]
    push word [bp+14]
    push word 0x400
    push word 0
    push dword 0
    call far SendMessage
    cmp ax, 0x3344
    jne fail
    cmp dx, 0x1122
    jne fail
    xor ax, ax
    xor dx, dx
    jmp .return
.nested:
    inc word [nested]
    mov ax, 0x3344
    mov dx, 0x1122
    jmp .return
.posted:
    cmp word [bp+10], 0x4321
    jne fail
    cmp dword [bp+6], 0x87654321
    jne fail
    mov ax, 0x1234
    mov dx, 0x5678
    jmp .return
.destroy:
    inc word [destroyed]
    xor ax, ax
    xor dx, dx
    jmp .return
.paint:
    inc word [painted]
    push word [bp+14]
    push ds
    push word ps
    call far BeginPaint
    mov [dc], ax
    push word [bp+14]
    push ds
    push word rect
    call far GetClientRect
    cmp word [rect+4], 160
    jae fail ; shared frame consumes part of the outer window
    push dword 0x00113322
    call far CreateSolidBrush
    push word [dc]
    push ds
    push word rect
    push ax
    call far FillRect
    push word [bp+14]
    push ds
    push word ps
    call far EndPaint
    xor ax, ax
    xor dx, dx
.return:
    pop bp
    retf 10
dlgproc:
    push bp
    mov bp, sp
    cmp word [bp+12], 0x110
    jne .other
    cmp dword [bp+6], 0xdeadbeef
    jne fail
    push word [bp+14]
    push word 100
    push word 1234
    push word 0
    call far SetDlgItemInt
    mov ax, 1
    jmp .return
.other:
    xor ax, ax
.return:
    mov dx, 0x7bad ; DLGPROC returns BOOL in AX only
    pop bp
    retf 10
segment _DATA public class=DATA use16
wc: dw 3
    dw wndproc, 0
    dw 0,0,0,0,0,16
    dd 0
    dw classname,0
dlg_template:
    dd 0x00c00000
    db 1
    dw 0,0,100,50
    db 0,0,'Dialog adapter',0
    dw 10,10,50,10,100
    dd 0x50810000
    db 0x81,0,0
translated: dw 0
dialog: dw 0
remaining: dw 0
bitmap: dw 0
old_bitmap: dw 0
initial_sp: dw 0
hwnd: dw 0
created: dw 0
nested: dw 0
painted: dw 0
destroyed: dw 0
dc: dw 0
ps: times 32 db 0
rect: times 8 db 0
msg: times 18 db 0
classname: db 'Win16Shared',0
title: db 'Shared guest window',0
passed: db 'WIN16 WINDOW PASS',0
failed: db 'WIN16 WINDOW FAIL',0
segment STACK stack class=STACK use16
    resb 8192
group DGROUP _DATA STACK
