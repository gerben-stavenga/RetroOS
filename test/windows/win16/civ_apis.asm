bits 16
segment _TEXT public class=CODE use16
extern Debug, Exit, GetTickCount, GlobalAlloc, GlobalLock, GlobalFree
extern IsBadReadPtr, IsBadWritePtr, IsBadCodePtr, IsBadHugeReadPtr, IsBadHugeWritePtr
extern CreateDIBitmap
extern hmemcpy, CreateBitmap, SetBitmapBits, CreateCompatibleDC, SelectObject
extern GetTextExtent, GetTextExtentPoint, GetPaletteEntries, GetTextAlign, GetBitmapDimensionEx
extern MoveToEx
extern GetNearestPaletteIndex
extern DeleteDC, DeleteObject, GetPixel, CreatePalette, SetPaletteEntries, AnimatePalette
extern GetBkMode, SetBkMode, GetOpenFileName, CommDlgExtendedError, sndPlaySound
extern SetBitmapDimension, GetBitmapDimension, SelectPalette, RealizePalette, BitBlt
extern IsDialogMessage
extern GetBitmapBits, FrameRect, GetStockObject, GetObject, CreatePatternBrush
extern RegisterClass, CreateDialogIndirect, DestroyWindow, DefDlgProc

global _start
_start:
    mov [initial_sp],sp
    mov ax,seg padded
    mov es,ax
    mov byte [es:31],0x5a
    cmp byte [es:31],0x5a
    jne fail
    push dword 0
    push word 1
    call far IsBadReadPtr
    cmp ax,1
    jne fail
    push ds
    push word initial_sp
    push word 2
    call far IsBadWritePtr
    test ax,ax
    jnz fail
    push cs
    push word _start
    call far IsBadCodePtr
    test ax,ax
    jnz fail
    push ds
    push word initial_sp
    call far IsBadCodePtr
    cmp ax,1
    jne fail
    push cs
    push word _start
    push word 1
    call far IsBadWritePtr
    cmp ax,1
    jne fail
    push dword 0
    push dword 0
    call far IsBadHugeWritePtr
    test ax,ax
    jnz fail
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
    push dword [source_pointer]
    push dword 70000
    call far IsBadHugeWritePtr
    test ax,ax
    jnz fail
    push dword [source_pointer]
    push dword 70001
    call far IsBadHugeReadPtr
    cmp ax,1
    jne fail
    push word [source_pointer+2]
    push word 65535
    push word 2
    call far IsBadReadPtr
    cmp ax,1
    jne fail
    push word [source_pointer+2]
    push word 65535
    push dword 2
    call far IsBadHugeReadPtr
    test ax,ax
    jnz fail
    push dword [source_pointer]
    push dword 0xffffffff
    call far IsBadHugeReadPtr
    cmp ax,1
    jne fail
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
    push dword [source_pointer]
    push word 1
    call far IsBadReadPtr
    cmp ax,1
    jne fail
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
    push ds
    push word extent_text
    push word 3
    push ds
    push word extent_size
    call far GetTextExtentPoint
    test ax,ax
    jz fail
    cmp dword [extent_size],0x00100018
    jne fail
    push word [dc]
    push ds
    push word extent_text
    push word 3
    call far GetTextExtent
    cmp ax,24
    jne fail
    cmp dx,16
    jne fail
    push word [dc]
    call far GetTextAlign
    test ax,ax
    jnz fail
    mov ax,[dc]
    push ax
    push word -5
    push word 37
    push dword 0
    call far MoveToEx
    test ax,ax
    jz fail
    push word [dc]
    push word 0
    push word 0
    push ds
    push word previous_point
    call far MoveToEx
    test ax,ax
    jz fail
    cmp word [previous_point],-5
    jne fail
    cmp word [previous_point+2],37
    jne fail
    push word [dc]
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
    push word 14
    push ds
    push word bitmap_info
    call far GetObject
    cmp ax,14
    jne fail
    cmp word [bitmap_info+6],2
    jne fail
    cmp word [bitmap_info+8],0x101
    jne fail
    ; Read actual DDB storage, including complete-row count semantics.
    push word [bitmap]
    push dword 0
    push ds
    push word readback
    call far GetBitmapBits
    or ax,dx
    jnz fail
    push word [bitmap]
    push dword 0
    push dword 0
    call far GetBitmapBits
    cmp ax,2
    jne fail
    push word [bitmap]
    push dword 1
    push ds
    push word readback
    call far GetBitmapBits
    or ax,dx
    jnz fail
    cmp word [readback],0xa55a
    jne fail
    push word [bitmap]
    push dword 2
    push ds
    push word readback
    call far GetBitmapBits
    cmp ax,2
    jne fail
    cmp word [readback],0x40
    jne fail
    push word [bitmap]
    call far CreatePatternBrush
    test ax,ax
    jz fail
    mov [pattern_brush],ax
    ; Drawing must invalidate the original upload for bitmap readback.
    push word 4
    call far GetStockObject
    push word [dc]
    push ds
    push word frame_rect
    push ax
    call far FrameRect
    test ax,ax
    jz fail
    push word [bitmap]
    push dword 2
    push ds
    push word readback
    call far GetBitmapBits
    cmp ax,2
    jne fail
    cmp word [readback],0
    jne fail
    push word [dc]
    push ds
    push word frame_rect
    push word [pattern_brush]
    call far FrameRect
    test ax,ax
    jz fail
    push word [bitmap]
    push dword 2
    push ds
    push word readback
    call far GetBitmapBits
    cmp word [readback],0x40
    jne fail
    push word [pattern_brush]
    call far DeleteObject
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
    push word [bitmap]
    push ds
    push word extent_size
    call far GetBitmapDimensionEx
    cmp dword [extent_size],0x0022000c
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
    push word 1
    push word 2
    push ds
    push word palette_result
    call far GetPaletteEntries
    cmp ax,1
    jne fail
    cmp dword [palette_result],0x0100ff00
    jne fail
    mov ax,[pal]
    push ax
    push dword 0x0000fe00
    call far GetNearestPaletteIndex
    cmp ax,1
    jne fail
    push word [pal]
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
    push word [dc]
    call far RealizePalette
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
    call far AnimatePalette
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
indices db 10,11
blue dd 0x01ff0000
frame_rect dw 0,0,8,1
pattern_brush dw 0
readback dw 0xa55a
bitmap_info times 14 db 0
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
previous_point dd 0
extent_text db "ABCmore",0
extent_size dd 0
palette_result times 2 dd 0
palette dw 0x300,2
entries dd 0x010000ff,0x0100ff00
passed db 'WIN16 CIV_APIS PASS',0
failed db 'WIN16 CIV_APIS FAIL',0
segment STACK stack class=STACK use16
resb 8192
group DGROUP _DATA STACK

segment PAD public class=FAR_DATA use16
padded times 17 db 0
