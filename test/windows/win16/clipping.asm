bits 16
segment _TEXT public class=CODE use16
extern Debug, Exit, CreateCompatibleDC, CreateCompatibleBitmap, SelectObject, DeleteDC, DeleteObject
extern IntersectClipRect, ExcludeClipRect, SelectClipRgn, PatBlt, GetPixel
%macro clip 6
    push word [dc]
    push word %2
    push word %3
    push word %4
    push word %5
    call far %1
    cmp ax,%6
    jne fail
%endmacro
%macro fill 1
    push word [dc]
    push word 0
    push word 0
    push word 10
    push word 10
    push dword %1
    call far PatBlt
    test ax,ax
    jz fail
%endmacro
%macro pixel 3
    push word [dc]
    push word %1
    push word %2
    call far GetPixel
    cmp ax,(%3 & 0xffff)
    jne fail
    cmp dx,(%3 >> 16)
    jne fail
%endmacro
global _start
_start:
    mov [initial_sp],sp
    push word 0
    call far CreateCompatibleDC
    test ax,ax
    jz fail
    mov [dc],ax
    push ax
    push word 10
    push word 10
    call far CreateCompatibleBitmap
    test ax,ax
    jz fail
    mov [bitmap],ax
    push word [dc]
    push ax
    call far SelectObject
    mov [old_bitmap],ax
    fill 0x42 ; BLACKNESS
    clip IntersectClipRect,-2,-2,8,8,2
    clip ExcludeClipRect,4,4,6,6,3
    fill 0xff0062 ; WHITENESS
    pixel 0,0,0xffffff
    pixel 4,4,0
    pixel 6,4,0xffffff
    pixel 8,2,0
    clip IntersectClipRect,3,3,3,8,1
    fill 0x42
    pixel 0,0,0xffffff
    push word [dc]
    push word 0
    call far SelectClipRgn
    cmp ax,2
    jne fail
    fill 0x42
    pixel 0,0,0
    push word [dc]
    push word [old_bitmap]
    call far SelectObject
    push word [dc]
    call far DeleteDC
    push word [bitmap]
    call far DeleteObject
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
segment _DATA public class=DATA use16
initial_sp dw 0
dc dw 0
bitmap dw 0
old_bitmap dw 0
passed db 'WIN16 CLIPPING PASS',0
failed db 'WIN16 CLIPPING FAIL',0
segment STACK stack class=STACK use16
    resb 8192
group DGROUP _DATA STACK
