bits 16
segment _TEXT public class=CODE use16
extern Debug, Exit, GetTickCount, GlobalAlloc, GlobalLock, GlobalFree
extern CreateDIBitmap
extern hmemcpy, CreateBitmap, SetBitmapBits, CreateCompatibleDC, SelectObject
extern DeleteDC, DeleteObject, GetPixel, CreatePalette, SetPaletteEntries
extern GetBkMode, SetBkMode, GetOpenFileName, CommDlgExtendedError, sndPlaySound
extern SetBitmapDimension, GetBitmapDimension, SelectPalette, RealizePalette, BitBlt
extern IsDialogMessage
extern RegisterClass, CreateDialogIndirect, DestroyWindow, DefDlgProc

global _start
_start:
    mov [initial_sp],sp
    mov ax,seg padded
    mov es,ax
    mov byte [es:31],0x5a
    cmp byte [es:31],0x5a
    jne fail
    call far GetTickCount
    push word 0x42
    push dword 70000
    call far GlobalAlloc
    test ax,ax
    jz fail
    mov [source],ax
    push ax
    call far GlobalLock
    cmp cx,dx
    jne fail
    mov [source_pointer],ax
    mov [source_pointer+2],dx
    mov es,dx
    mov word [es:0],0x1234
    add dx,8
    mov es,dx
    mov word [es:4462],0x5678
    push word 0x42
    push dword 70000
    call far GlobalAlloc
    test ax,ax
    jz fail
    mov [destination],ax
    push ax
    call far GlobalLock
    mov [destination_pointer],ax
    mov [destination_pointer+2],dx
    push dword [destination_pointer]
    push dword [source_pointer]
    push dword 70000
    call far hmemcpy
    mov es,[destination_pointer+2]
    cmp word [es:0],0x1234
    jne fail
    mov ax,es
    add ax,8
    mov es,ax
    cmp word [es:4462],0x5678
    jne fail
    push word [source]
    call far GlobalFree
    test ax,ax
    jnz fail
    push word [destination]
    call far GlobalFree
    test ax,ax
    jnz fail
    push word 8
    push word 1
    push word 1
    push word 1
    push ds
    push word bits_a
    call far CreateBitmap
    test ax,ax
    jz fail
    mov [bitmap],ax
    push word 0
    call far CreateCompatibleDC
    mov [dc],ax
    push ax
    push word [bitmap]
    call far SelectObject
    mov [old_bitmap],ax
    push word [dc]
    push word 0
    push word 0
    call far GetPixel
    cmp ax,0xffff
    jne fail
    cmp dx,0xff
    jne fail
    push word [bitmap]
    push dword 2
    push ds
    push word bits_b
    call far SetBitmapBits
    cmp ax,2
    jne fail
    push word [dc]
    push word 0
    push word 0
    call far GetPixel
    or ax,dx
    jnz fail
    push word [dc]
    push word 1
    push word 0
    call far GetPixel
    cmp ax,0xffff
    jne fail
    cmp dx,0xff
    jne fail
    push word [bitmap]
    push word 12
    push word 34
    call far SetBitmapDimension
    push word [bitmap]
    call far GetBitmapDimension
    cmp ax,12
    jne fail
    cmp dx,34
    jne fail
    push word [dc]
    push word 1
    call far SetBkMode
    push word [dc]
    call far GetBkMode
    cmp ax,1
    jne fail
    push word [dc]
    push word [old_bitmap]
    call far SelectObject
    push word [dc]
    call far DeleteDC
    push word [bitmap]
    call far DeleteObject
    push word 0
    push ds
    push word dib_header
    push dword 4
    push ds
    push word dib_bits
    push ds
    push word dib_info
    push word 0
    call far CreateDIBitmap
    test ax,ax
    jz fail
    mov [bitmap],ax
    push word 0
    call far CreateCompatibleDC
    mov [dc],ax
    push ax
    push word [bitmap]
    call far SelectObject
    mov [old_bitmap],ax
    push word [dc]
    push word 0
    push word 0
    call far GetPixel
    cmp ax,0xff00
    jne fail
    test dx,dx
    jnz fail
    push word [dc]
    push word [old_bitmap]
    call far SelectObject
    push word [bitmap]
    call far DeleteObject
    push word [dc]
    call far DeleteDC
    push ds
    push word palette
    call far CreatePalette
    test ax,ax
    jz fail
    mov [pal],ax
    push ax
    push word 0
    push word 1
    push ds
    push word entries
    call far SetPaletteEntries
    cmp ax,1
    jne fail
    push word 2
    push word 1
    push word 1
    push word 8
    push ds
    push word indices
    call far CreateBitmap
    test ax,ax
    jz fail
    mov [bitmap],ax
    push word 0
    call far CreateCompatibleDC
    mov [dc],ax
    push ax
    push word [bitmap]
    call far SelectObject
    mov [old_bitmap],ax
    push word [dc]
    push word [pal]
    push word 0
    call far SelectPalette
    test ax,ax
    jz fail
    mov [old_palette],ax
    call indexed_blit
    push word [dc]
    push word 0
    push word 0
    call far GetPixel
    cmp ax,0xff
    jne fail
    test dx,dx
    jnz fail
    push word [pal]
    push word 0
    push word 1
    push ds
    push word blue
    call far SetPaletteEntries
    call indexed_blit
    push word [dc]
    push word 0
    push word 0
    call far GetPixel
    test ax,ax
    jnz fail
    cmp dx,0xff
    jne fail
    ; Memory DCs using the default palette still see the realized device palette.
    push word [dc]
    call far RealizePalette
    push word [dc]
    push word [old_palette]
    push word 0
    call far SelectPalette
    ; A composed bitmap must survive being used as a subsequent blit source.
    push word 2
    push word 1
    push word 1
    push word 8
    push dword 0
    call far CreateBitmap
    mov [copy_bitmap],ax
    push word 0
    call far CreateCompatibleDC
    mov [copy_dc],ax
    push ax
    push word [copy_bitmap]
    call far SelectObject
    mov si,[dc]
    mov di,[copy_dc]
    call copy_blit
    mov si,[copy_dc]
    mov di,[dc]
    call copy_blit
    push word [dc]
    push word 0
    push word 0
    call far GetPixel
    test ax,ax
    jnz fail
    cmp dx,0xff
    jne fail
    push word [copy_dc]
    call far DeleteDC
    push word [copy_bitmap]
    call far DeleteObject
    push word [dc]
    push word [pal]
    push word 0
    call far SelectPalette
    push word [dc]
    push word [old_palette]
    push word 0
    call far SelectPalette
    cmp ax,[pal]
    jne fail
    push word [dc]
    push word [old_bitmap]
    call far SelectObject
    push word [bitmap]
    call far DeleteObject
    push word [dc]
    call far DeleteDC
    push word [pal]
    call far DeleteObject
    test ax,ax
    jz fail
    push dword 0
    call far GetOpenFileName
    test ax,ax
    jnz fail
    call far CommDlgExtendedError
    cmp ax,2
    jne fail
    test dx,dx
    jnz fail
    push dword 0
    push word 0
    call far sndPlaySound
    test ax,ax
    jnz fail
    ; A custom dialog class forwards WM_NCCREATE through DefDlgProc.
    ; Wrong argument offsets reject creation before WM_INITDIALOG.
    mov [window_class+10],ds
    mov [window_class+2],word dialog_window_proc
    mov [window_class+4],cs
    mov [window_class+24],ds
    push ds
    push word window_class
    call far RegisterClass
    test ax,ax
    jz fail
    push ds
    push ds
    push word dialog_template
    push word 0
    push cs
    push word dialog_proc
    call far CreateDialogIndirect
    test ax,ax
    jz fail
    cmp word [dialog_initialized],1
    jne fail
    mov [dialog_message],ax
    push ax
    push ds
    push word dialog_message
    call far IsDialogMessage
    test ax,ax
    jz fail
    cmp word [dialog_dispatched],1
    jne fail
    push word [dialog_message]
    call far DestroyWindow
    mov ah,1
    xor cx,cx
    xor dx,dx
    int 0x1a
    call far GetTickCount
    mov si,ax
.wait_clock:
    call far GetTickCount
    sub ax,si
    cmp ax,120
    jb .wait_clock
    xor ax,ax
    int 0x1a
    test dx,dx
    jz fail
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
indexed_blit:
    mov si,[dc]
    mov di,si
copy_blit:
    push di
    push word 0
    push word 0
    push word 2
    push word 1
    push si
    push word 0
    push word 0
    push dword 0xcc0020
    call far BitBlt
    test ax,ax
    jz fail
    ret
dialog_window_proc:
    jmp far DefDlgProc
dialog_proc:
    push bp
    mov bp,sp
    cmp word [bp+12],0x480
    jne .init
    mov word [dialog_dispatched],1
.init:
    cmp word [bp+12],0x110
    jne .done
    mov word [dialog_initialized],1
.done:
    xor ax,ax
    xor dx,dx
    pop bp
    retf 10
segment _DATA public class=DATA use16
window_class:
    dw 0
    dd 0
    dw 0,30,0,0,0,0
    dd 0
    dw class_name,0
class_name db 'CivApiDialog',0
dialog_template:
    dd 0x80000000
    db 0
    dw 0,0,32,32
    db 0,'CivApiDialog',0,'Adapter test',0
dialog_initialized dw 0
dialog_dispatched dw 0
dialog_message dw 0,0x480,0
    dd 0,0
    dw 0,0
initial_sp dw 0
source dw 0
destination dw 0
source_pointer dd 0
destination_pointer dd 0
bitmap dw 0
dc dw 0
old_bitmap dw 0
pal dw 0
old_palette dw 0
copy_bitmap dw 0
copy_dc dw 0
indices db 0,1
blue dd 0xff0000
bits_a db 0x80,0
bits_b db 0x40,0
dib_header:
    dd 40,1,1
    dw 1,8
    dd 0,4,0,0,2,0
    dd 0,0 ; deliberately not the initialization palette
 dib_info:
    dd 40,1,1
    dw 1,8
    dd 0,4,0,0,2,0
    dd 0,0xff00
 dib_bits db 1,0,0,0
palette dw 0x300,2
entries dd 0xff,0xff00
passed db 'WIN16 CIV_APIS PASS',0
failed db 'WIN16 CIV_APIS FAIL',0
segment STACK stack class=STACK use16
resb 8192
group DGROUP _DATA STACK

segment PAD public class=FAR_DATA use16
padded times 17 db 0
