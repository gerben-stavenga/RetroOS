bits 16
segment _TEXT public class=CODE use16
extern GetPrivateProfileString
extern PatBlt
extern SetTextAlign, ExtFloodFill, ExtTextOut, SetBkColor
extern SetProp, GetProp, RemoveProp
extern InitTask
extern Exit, Debug, RegisterClass, CreateWindow, DestroyWindow, DefWindowProc
extern SendMessage, UpdateWindow, BeginPaint, EndPaint, GetClientRect
extern PostMessage, GetMessage, DispatchMessage, FillRect, CreateSolidBrush, GetPixel, GetDC, ReleaseDC
extern CreateDC, CreateBitmap, SelectObject, DeleteDC, DeleteObject, SetPixel
extern GetWindowWord, SetWindowWord, GetWindowLong, SetWindowLong, CallWindowProc
extern LocalAlloc, LocalLock, LocalUnlock, LocalFree, LocalReAlloc
extern MessageBox, SetTimer, KillTimer, GetFocus, GetParent, IsWindowEnabled
extern SetScrollRange, SetScrollPos
extern ShowWindow, GetWindowRect, GetTickCount
extern DOSExit, CreateDialog, SetDlgItemInt, GetDlgItemInt
extern GetCursorPos, SetCursorPos, ClientToScreen, ScreenToClient
extern wvsprintf, WinExec
extern _lopen, _lclose, _lread, _lcreat, _llseek, _lwrite
extern GetTempFileName, LoadLibrary, FreeLibrary, GetModuleHandle, GetProcAddress, GetModuleUsage
extern GetDriveType
extern GlobalAlloc, GlobalLock, GlobalUnlock, GlobalFree, GlobalSize, GlobalReAlloc, GlobalHandle
extern AllocCStoDSAlias, FreeSelector
extern GlobalAddAtom, GlobalFindAtom, GlobalDeleteAtom, GlobalGetAtomName
global _start
_start:
    call far InitTask
    test ax, ax
    jz installer_fail
    cmp bx, 0x100
    jae installer_fail
    cmp dword [es:bx], 'prob'
    jne installer_fail
    cmp word [es:bx+4], 'e'
    jne installer_fail
    push ds
    pop es
    mov [initial_sp], sp
    push ds
    push word ini_section
    push ds
    push word ini_key
    push ds
    push word ini_default
    push ds
    push word ini_result
    push word 32
    push ds
    push word ini_path
    call far GetPrivateProfileString
    cmp ax, 6
    jne installer_fail
    cmp dword [ini_result], 'C:\C'
    jne installer_fail
    cmp word [ini_result+4], 'IV'
    jne installer_fail
    push word 0x42
    push dword 16
    call far GlobalAlloc
    test ax,ax
    jz installer_fail
    mov [test_global],ax
    push ax
    call far GlobalLock
    test dx,dx
    jz installer_fail
    mov es,dx
    mov bx,ax
    cmp byte [es:bx],0
    jne installer_fail
    mov byte [es:bx],0x5a
    push ds
    pop es
    push word [test_global]
    call far GlobalUnlock
    push word [test_global]
    push dword 32
    push word 2
    call far GlobalReAlloc
    test ax,ax
    jz installer_fail
    mov [test_global],ax
    push ax
    call far GlobalSize
    cmp ax,32
    jne installer_fail
    test dx,dx
    jnz installer_fail
    push word [test_global]
    call far GlobalLock
    mov es,dx
    mov bx,ax
    cmp byte [es:bx],0x5a
    jne installer_fail
    push dx
    call far GlobalHandle
    cmp ax,[test_global]
    jne installer_fail
    push ds
    pop es
    push word [test_global]
    call far GlobalUnlock
    push word [test_global]
    call far GlobalFree
    test ax,ax
    jnz installer_fail
    push cs
    call far AllocCStoDSAlias
    test ax,ax
    jz installer_fail
    push ax
    call far FreeSelector
    test ax,ax
    jnz installer_fail

    push ds
    push word atom_name
    call far GlobalAddAtom
    cmp ax,0xc000
    jb installer_fail
    mov [test_atom],ax
    push ds
    push word atom_lower
    call far GlobalAddAtom
    cmp ax,[test_atom]
    jne installer_fail
    push word [test_atom]
    push ds
    push word atom_buffer
    push word 32
    call far GlobalGetAtomName
    cmp ax,9
    jne installer_fail
    cmp word [atom_buffer],0x6e49
    jne installer_fail
    push word [test_atom]
    call far GlobalDeleteAtom
    push ds
    push word atom_lower
    call far GlobalFindAtom
    cmp ax,[test_atom]
    jne installer_fail
    push word [test_atom]
    call far GlobalDeleteAtom
    push ds
    push word atom_name
    call far GlobalFindAtom
    test ax,ax
    jnz installer_fail

    push ds
    push word kernel_name
    call far GetModuleHandle
    test ax,ax
    jz installer_fail
    push ax
    push ds
    push word version_name
    call far GetProcAddress
    mov [installer_proc],ax
    mov [installer_proc+2],dx
    or ax,dx
    jz installer_fail
    call far [installer_proc]
    cmp ax,0x0a03
    jne installer_fail
    push ds
    push word lz_name
    call far LoadLibrary
    cmp ax,32
    jb installer_fail
    mov [lz_module],ax
    push ax
    push ds
    push word lz_copy_name
    call far GetProcAddress
    mov [installer_proc],ax
    mov [installer_proc+2],dx
    or ax,dx
    jz installer_fail
    push word [lz_module]
    push dword 1
    call far GetProcAddress
    cmp ax,[installer_proc]
    jne installer_fail
    cmp dx,[installer_proc+2]
    jne installer_fail
    push word 0xc3
    push ds
    push word temp_prefix
    push word 0
    push ds
    push word temp_one
    call far GetTempFileName
    test ax,ax
    jz installer_fail
    mov [temp_unique],ax
    push word 0xc3
    push ds
    push word temp_prefix
    push word 0
    push ds
    push word temp_two
    call far GetTempFileName
    test ax,ax
    jz installer_fail
    cmp ax,[temp_unique]
    je installer_fail
    push ds
    push word temp_one
    push word 2
    call far _lopen
    cmp ax,0xffff
    je installer_fail
    mov [lz_source],ax
    push ax
    push ds
    push word compressed
    push word compressed_end-compressed
    call far _lwrite
    cmp ax,compressed_end-compressed
    jne installer_fail
    push word [lz_source]
    push dword 0
    push word 0
    call far _llseek
    push ds
    push word temp_two
    push word 2
    call far _lopen
    cmp ax,0xffff
    je installer_fail
    mov [lz_dest],ax
    push word [lz_source]
    push ax
    call far [installer_proc]
    cmp ax,9
    jne installer_fail
    test dx,dx
    jnz installer_fail
    push word [lz_dest]
    push dword 0
    push word 0
    call far _llseek
    push word [lz_dest]
    push ds
    push word expanded
    push word 9
    call far _lread
    cmp ax,9
    jne installer_fail
    cmp word [expanded],0x6261
    jne installer_fail
    cmp word [expanded+6],0x6261
    jne installer_fail
    cmp byte [expanded+8],'c'
    jne installer_fail
    push word [lz_source]
    call far _lclose
    push word [lz_dest]
    call far _lclose
    push ds
    push word lz_name
    call far LoadLibrary
    cmp ax,[lz_module]
    jne installer_fail
    push ax
    call far GetModuleUsage
    cmp ax,2
    jne installer_fail
    push word [lz_module]
    call far FreeLibrary
    push word [lz_module]
    call far GetModuleUsage
    cmp ax,1
    jne installer_fail
    cmp sp,[initial_sp]
    jne installer_fail

    push ds
    push word file_missing
    push word 1
    call far WinExec
    cmp ax,2
    jne fail
    mov word [format_args+4],ds
    push ds
    push word format_buffer
    push ds
    push word format_text
    push ds
    push word format_args
    call far wvsprintf
    cmp ax,16
    jne fail
    cmp word [format_buffer],0x322d
    jne fail
    cmp word [format_buffer+3],0x6568
    jne fail
    cmp word [format_buffer+9],0x3030
    jne fail
    cmp word [format_buffer+11],0x4132
    jne fail
    cmp word [format_buffer+14],0x3037
    jne fail

    push ds
    push word file_missing
    push word 0
    call far _lopen
    cmp ax,0xffff
    jne file_fail_1
    push ds
    push word file_path
    push word 0
    call far _lcreat
    cmp ax,0xffff
    je file_fail_2
    mov [file_handle],ax
    push ax
    push ds
    push word file_payload
    push word 5
    call far _lwrite
    cmp ax,5
    jne file_fail_3
    push word [file_handle]
    call far _lclose
    test ax,ax
    jnz file_fail_4
    push ds
    push word file_path
    push word 2
    call far _lopen
    cmp ax,0xffff
    je file_fail_5
    mov [file_handle],ax
    push ax
    push dword -2
    push word 2
    call far _llseek
    cmp ax,3
    jne file_fail_6
    test dx,dx
    jnz file_fail_7
    push word [file_handle]
    push ds
    push word file_buffer
    push word 5
    call far _lread
    cmp ax,2
    jne file_fail_8
    cmp word [file_buffer],0x6f6c
    jne file_fail_9
    push word [file_handle]
    push dword 2
    push word 0
    call far _llseek
    cmp ax,2
    jne file_fail_10
    push word [file_handle]
    push dword 0
    push word 0
    call far _lwrite
    test ax,ax
    jnz file_fail_11
    push word [file_handle]
    push dword 0
    push word 2
    call far _llseek
    cmp ax,2
    jne file_fail_12
    push word [file_handle]
    call far _lclose
    test ax,ax
    jnz file_fail_13
    push word [file_handle]
    call far _lclose
    cmp ax,0xffff
    jne file_fail_14
    cmp sp,[initial_sp]
    jne file_fail_15
    push word 2
    call far GetDriveType
    cmp ax,3
    jne pmdos_fail
    push word 26
    call far GetDriveType
    test ax,ax
    jnz pmdos_fail
    mov ax,0x150b
    mov cx,2
    int 0x2f
    test ax,ax
    jnz pmdos_fail
    cmp bx,0xadad
    jne pmdos_fail
    mov ax,0x150b
    mov cx,3
    int 0x2f
    test ax,ax
    jz pmdos_fail
    cmp bx,0xadad
    jne pmdos_fail
    push ds
    mov ax,0x1c00
    mov dx,3
    int 0x21
    cmp al,8
    jne .allocation_fail
    cmp cx,512
    jne .allocation_fail
    cmp byte [bx],0xf8
    jne .allocation_fail
    pop ds
    jmp .allocation_done
.allocation_fail:
    pop ds
    jmp pmdos_fail
.allocation_done:
    push es
    mov ah,0x62
    int 0x21
    mov es,bx
    cmp word [es:0],0x20cd
    pop es
    jne pmdos_fail
    mov ah,0x50
    call far DOSExit
    jc pmdos_fail
    ; Direct PMDOS and DOS3Call use selectors and the same file/directory
    ; state as KERNEL's Windows APIs. Poison high halves like a 16-bit client.
    mov edx,0xabcd0002
    mov ax,0x0e00
    int 0x21
    mov ah,0x19
    call far DOSExit
    cmp al,2
    jne pmdos_fail
    mov dx,pm_directory
    mov ah,0x39
    int 0x21
    jc pmdos_fail
    mov dx,pm_directory
    mov ah,0x3b
    call far DOSExit
    jc pmdos_fail
    push ds
    push word pm_relative_file
    push word 0
    call far _lcreat
    cmp ax,0xffff
    je pmdos_fail
    mov [file_handle],ax
    mov bx,ax
    mov edx,0xabcd0000
    mov dx,file_payload
    mov ecx,0x12340005
    mov ax,0x4000
    int 0x21
    jc pmdos_fail
    cmp ax,5
    jne pmdos_fail
    cmp ecx,0x12340005
    jne pmdos_fail
    shr edx,16
    cmp dx,0xabcd
    jne pmdos_fail
    mov bx,[file_handle]
    xor cx,cx
    xor dx,dx
    mov ax,0x4200
    call far DOSExit
    jc pmdos_fail
    mov dx,file_buffer
    mov cx,5
    mov ah,0x3f
    int 0x21
    jc pmdos_fail
    cmp ax,5
    jne pmdos_fail
    cmp word [file_buffer],0x6568
    jne pmdos_fail
    push word [file_handle]
    call far _lclose
    test ax,ax
    jnz pmdos_fail
    mov dx,pm_root
    mov ah,0x3b
    int 0x21
    jc pmdos_fail
    push ds
    push word pm_absolute_file
    push word 0
    call far _lopen
    cmp ax,0xffff
    je pmdos_fail
    mov bx,ax
    mov ah,0x3e
    call far DOSExit
    jc pmdos_fail
    mov dx,pm_absolute_file
    mov ax,0x3d00
    int 0x21
    jc pmdos_fail
    push ax
    call far _lclose
    test ax,ax
    jnz pmdos_fail
    mov bx,0xffff
    mov ah,0x3e
    int 0x21
    jnc pmdos_fail
    cmp ax,6
    jne pmdos_fail
    cmp sp,[initial_sp]
    jne pmdos_fail
    push word 123
    push word 234
    call far SetCursorPos
    push ds
    push word cursor_point
    call far GetCursorPos
    cmp word [cursor_point],123
    jne fail
    cmp word [cursor_point+2],234
    jne fail
    mov ah, 0x2c
    call far DOSExit
    mov [clock_sample], dx
    call far GetTickCount
    mov [clock_start], ax
.clock_wait:
    call far GetTickCount
    sub ax, [clock_start]
    cmp ax, 30
    jb .clock_wait
    mov ah, 0x2c
    call far DOSExit
    cmp dx, [clock_sample]
    je fail
    cmp dl, 100
    jae fail
    cmp dh, 60
    jae fail

    push word 0x42
    push word 32
    call far LocalAlloc
    test ax, ax
    jz fail
    mov [local_block], ax
    push ax
    call far LocalLock
    mov bx, [local_block]
    cmp ax, [bx]
    jne fail
    test ax, ax
    jz fail
    mov bx, ds
    cmp dx, bx
    jne fail
    mov bx, ax
    cmp word [bx], 0
    jne fail
    cmp word [bx+30], 0
    jne fail
    mov word [bx], 0xbeef
    push word [local_block]
    push word 64
    push word 0x42
    call far LocalReAlloc
    cmp ax, [local_block]
    jne fail
    mov bx, ax
    mov bx, [bx]
    cmp word [bx], 0xbeef
    jne fail
    cmp word [bx+62], 0
    jne fail
    push word [local_block]
    call far LocalUnlock
    test ax, ax
    jnz fail
    push word [local_block]
    call far LocalFree
    test ax, ax
    jnz fail
    push word [local_block]
    call far LocalLock
    or ax, dx
    jnz fail
    push word 0x42
    push word 32
    call far LocalAlloc
    cmp ax, [local_block]
    jne fail
    push ax
    call far LocalLock
    mov bx, ax
    cmp word [bx], 0
    jne fail
    push word [local_block]
    call far LocalUnlock
    push word [local_block]
    call far LocalFree
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
    push word 6 ; TA_CENTER
    call far SetTextAlign
    test ax, ax
    jnz fail
    push word [dc]
    push word 0
    call far SetTextAlign
    cmp ax, 6
    jne fail
    push word [dc]
    push word 0
    push word 0
    push dword 0x00113322
    push word 1 ; FLOODFILLSURFACE, default white brush
    call far ExtFloodFill
    test ax, ax
    jz fail
    push word [dc]
    push word 0
    push word 0
    call far GetPixel
    cmp ax, 0xffff
    jne fail
    cmp dx, 0x00ff
    jne fail
    push word [dc]
    push dword 0x00112233
    call far SetBkColor
    push word [dc]
    push word 0
    push word 0
    push word 6 ; ETO_OPAQUE | ETO_CLIPPED
    push ds
    push word tiny_rect
    push dword 0
    push word 0
    push dword 0
    call far ExtTextOut
    test ax, ax
    jz fail
    push word [dc]
    push word 0
    push word 0
    call far GetPixel
    cmp ax, 0x2233
    jne fail
    cmp dx, 0x11
    jne fail
    push word [dc]
    push word 0
    push word 0
    push word 1
    push word 1
    push dword 0x00550009 ; DSTINVERT
    call far PatBlt
    test ax, ax
    jz fail
    push word [dc]
    push word 0
    push word 0
    call far GetPixel
    cmp ax, 0xddcc
    jne fail
    cmp dx, 0xee
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
    push ax
    push ds
    push word cursor_point
    call far ClientToScreen
    push word [hwnd]
    push ds
    push word cursor_point
    call far ScreenToClient
    cmp word [cursor_point],123
    jne fail
    cmp word [cursor_point+2],234
    jne fail
    cmp word [size_kind], 0
    jne fail
    cmp word [created], 1
    jne fail
    cmp word [nested], 1
    jne fail
    push word [hwnd]
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
    ; Maximize must change geometry and notify the Win16 procedure. Repeating
    ; it must not overwrite the normal placement needed by SW_RESTORE.
    push word [hwnd]
    push word 3
    call far ShowWindow
    cmp word [size_kind], 2
    jne fail
    push word [hwnd]
    push word 3
    call far ShowWindow
    push word [hwnd]
    push ds
    push word rect
    call far GetWindowRect
    cmp word [rect+4], 1024
    jne fail
    cmp word [rect+6], 768
    jne fail
    push word [hwnd]
    push word 9
    call far ShowWindow
    cmp word [size_kind], 0
    jne fail
    push word [hwnd]
    push ds
    push word rect
    call far GetWindowRect
    cmp word [rect], 10
    jne fail
    cmp word [rect+2], 10
    jne fail
    cmp word [rect+4], 170
    jne fail
    cmp word [rect+6], 130
    jne fail
    ; A segmented WINDOWPOS with NOMOVE|NOSIZE must not emit WM_SIZE
    ; when forwarded through shared DefWindowProc.
    mov ax, [hwnd]
    mov [position], ax
    mov word [size_kind], 0xffff
    push ax
    push word 0x47
    push word 0
    push ds
    push word position
    call far DefWindowProc
    cmp word [size_kind], 0xffff
    jne fail
    ; A Win16 subclass must be able to call and restore a shared 32-bit
    ; control procedure, including segmented text buffers and command packing.
    push ds
    push word button_class
    push ds
    push word button_title
    push dword 0x50000000
    push word 2
    push word 2
    push word 80
    push word 24
    push word [hwnd]
    push word 77
    push ds
    push dword 0
    call far CreateWindow
    test ax, ax
    jz fail
    mov [button], ax
    push ax
    push ds
    push word button_title
    push word 0x4321
    call far SetProp
    test ax, ax
    jz fail
    push word [button]
    push ds
    push word button_title
    call far GetProp
    cmp ax, 0x4321
    jne fail
    push word [button]
    push ds
    push word button_title
    call far RemoveProp
    cmp ax, 0x4321
    jne fail
    push word [button]
    push ds
    push word button_title
    call far GetProp
    test ax, ax
    jnz fail
    push word [button]
    push word -12
    call far GetWindowWord
    cmp ax, 77
    jne fail
    push word [button]
    push word -12
    push word 78
    call far SetWindowWord
    cmp ax, 77
    jne fail
    push word [button]
    push word -4
    call far GetWindowLong
    mov [button_proc], ax
    mov [button_proc+2], dx
    ; Native class procedures must be readable and directly far-callable.
    mov es, dx
    mov bx, ax
    cmp byte [es:bx], 0x68
    jne fail
    push ds
    pop es
    push word [button]
    push word 0x000e ; WM_GETTEXTLENGTH
    push word 0
    push dword 0
    call far [button_proc]
    cmp ax, 6
    jne fail
    push word [button]
    push word -4
    push cs
    push word button_subclass
    call far SetWindowLong
    cmp ax, [button_proc]
    jne fail
    cmp dx, [button_proc+2]
    jne fail
    push word [button]
    call far UpdateWindow
    push word [button]
    push word 0xd
    push word 16
    push ds
    push word button_text
    call far SendMessage
    cmp ax, 6
    jne fail
    cmp dword [button_text], 'butt'
    jne fail
    cmp word [button_text+4], 'on'
    jne fail
    push word [button]
    push word 0xf5
    push word 0
    push dword 0
    call far SendMessage
    cmp word [clicked], 1
    jne fail
    push word [button]
    push word -4
    push dword [button_proc]
    call far SetWindowLong
    cmp ax, button_subclass
    jne fail
    mov bx, cs
    cmp dx, bx
    jne fail
    push word [button]
    call far DestroyWindow
    ; Two-byte access to the last extra-byte slot must not require four bytes.
    push word [hwnd]
    push word 0
    push word 0xbeef
    call far SetWindowWord
    test ax, ax
    jnz fail
    push word [hwnd]
    push word 0
    call far GetWindowWord
    cmp ax, 0xbeef
    jne fail
    ; Shared vertical scrollbar: drag through its thumb and let the NE
    ; parent update position in response to WM_VSCROLL.
    push ds
    push word scroll_class
    push dword 0
    push dword 0x50000001
    push word 2
    push word 2
    push word 16
    push word 128
    push word [hwnd]
    push word 79
    push ds
    push dword 0
    call far CreateWindow
    mov [scroll], ax
    test ax, ax
    jz fail
    push ax
    push word 2
    push word -10
    push word 30
    push word 1
    call far SetScrollRange
    cmp ax, 1
    jne fail
    push word [scroll]
    push word 2
    push word 10
    push word 1
    call far SetScrollPos
    push word [scroll]
    push word 0x201
    push word 1
    push dword 0x00400008
    call far SendMessage
    push word [scroll]
    push word 0x200
    push word 1
    push dword 0x00680008
    call far SendMessage
    push word [scroll]
    push word 0x202
    push word 0
    push dword 0x00680008
    call far SendMessage
    cmp word [scroll_events], 7
    jne fail
    push word [scroll]
    push word 0xe1
    push word 0
    push dword 0
    call far SendMessage
    cmp ax, 30
    jne fail
    push word [scroll]
    call far DestroyWindow
    ; The modal box must display actual buttons and return the selected IDNO,
    ; not the old unconditional IDOK kernel result.
    push word 0
    push word 0
    push word 20
    push cs
    push word messagebox_timer
    call far SetTimer
    mov [timer_id], ax
    push word [hwnd]
    push ds
    push word question
    push ds
    push word question_title
    push word 0x104
    call far MessageBox
    cmp ax, 7
    jne fail
    push word [hwnd]
    call far IsWindowEnabled
    cmp ax, 1
    jne fail
    ; Win16 LB_* numbers and far strings reach the shared list control.
    push ds
    push word list_class
    push ds
    push word list_empty
    push dword 0x50000001
    push word 10
    push word 10
    push word 100
    push word 40
    push word [hwnd]
    push word 77
    push ds
    push dword 0
    call far CreateWindow
    mov [list_hwnd], ax
    test ax, ax
    jz fail
    push ax
    push word 0x401
    push word 0
    push ds
    push word list_text
    call far SendMessage
    test ax, ax
    jnz fail
    push word [list_hwnd]
    push word 0x40c
    push word 0
    push dword 0
    call far SendMessage
    cmp ax, 1
    jne fail
    push word [list_hwnd]
    push word 0x40a
    push word 0
    push ds
    push word list_buffer
    call far SendMessage
    cmp ax, 5
    jne fail
    cmp word [list_buffer], 0x7041
    jne fail
    push word [list_hwnd]
    push word 0x407
    push word 0
    push dword 0
    call far SendMessage
    test ax, ax
    jnz fail
    push word [list_hwnd]
    call far UpdateWindow
    push word [list_hwnd]
    call far GetDC
    mov [dc], ax
    push ax
    push word 90
    push word 5
    call far GetPixel
    test ax, ax
    jnz fail
    cmp dx, 0x80
    jne fail
    push word [list_hwnd]
    push word [dc]
    call far ReleaseDC
    push word [list_hwnd]
    call far DestroyWindow
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
file_fail_1:
    push ds
    push word file_error_1
    call far Debug
    jmp fail
file_fail_2:
    push ds
    push word file_error_2
    call far Debug
    jmp fail
file_fail_3:
    push ds
    push word file_error_3
    call far Debug
    jmp fail
file_fail_4:
    push ds
    push word file_error_4
    call far Debug
    jmp fail
file_fail_5:
    push ds
    push word file_error_5
    call far Debug
    jmp fail
file_fail_6:
    push ds
    push word file_error_6
    call far Debug
    jmp fail
file_fail_7:
    push ds
    push word file_error_7
    call far Debug
    jmp fail
file_fail_8:
    push ds
    push word file_error_8
    call far Debug
    jmp fail
file_fail_9:
    push ds
    push word file_error_9
    call far Debug
    jmp fail
file_fail_10:
    push ds
    push word file_error_10
    call far Debug
    jmp fail
file_fail_11:
    push ds
    push word file_error_11
    call far Debug
    jmp fail
file_fail_12:
    push ds
    push word file_error_12
    call far Debug
    jmp fail
file_fail_13:
    push ds
    push word file_error_13
    call far Debug
    jmp fail
file_fail_14:
    push ds
    push word file_error_14
    call far Debug
    jmp fail
file_fail_15:
    push ds
    push word file_error_15
    call far Debug
    jmp fail
installer_fail:
    push ds
    push word installer_error
    call far Debug
    jmp fail
pmdos_fail:
    push ds
    push word pm_error
    call far Debug
fail:
    push ds
    push word failed
    call far Debug
    push word 1
    call far Exit
wndproc:
    push bp
    mov bp, sp
    cmp word [bp+12], 0x115
    je .scroll
    cmp word [bp+12], 0x111
    je .command
    cmp word [bp+12], 5
    je .size
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
.scroll:
    mov ax, [scroll]
    cmp [bp+8], ax
    jne fail
    mov ax, [bp+10]
    cmp ax, 8
    je .scroll_end
    cmp word [bp+6], 30
    jne fail
    cmp ax, 5
    je .scroll_track
    cmp ax, 4
    jne fail
    or word [scroll_events], 2
    jmp .scroll_position
.scroll_track:
    or word [scroll_events], 1
.scroll_position:
    push word [scroll]
    push word 2
    push word [bp+6]
    push word 1
    call far SetScrollPos
    jmp .scroll_return
.scroll_end:
    or word [scroll_events], 4
.scroll_return:
    xor ax, ax
    xor dx, dx
    jmp .return
.command:
    cmp word [bp+10], 78
    jne fail
    mov ax, [button]
    cmp word [bp+6], ax
    jne fail
    cmp word [bp+8], 0
    jne fail
    inc word [clicked]
    xor ax, ax
    xor dx, dx
    jmp .return
.size:
    mov ax, [bp+10]
    mov [size_kind], ax
    xor ax, ax
    xor dx, dx
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
messagebox_timer:
    push bp
    mov bp, sp
    push word 0
    push word [timer_id]
    call far KillTimer
    push word [hwnd]
    call far IsWindowEnabled
    test ax, ax
    jnz fail
    call far GetFocus
    mov [message_button], ax
    push ax
    push word -12
    call far GetWindowWord
    cmp ax, 7
    jne fail
    push word [message_button]
    call far GetParent
    push ax
    push word 0x111
    push word 7
    push dword 0
    call far SendMessage
    xor ax, ax
    xor dx, dx
    pop bp
    retf 10
button_subclass:
    push bp
    mov bp, sp
    push dword [button_proc]
    push word [bp+14]
    push word [bp+12]
    push word [bp+10]
    push dword [bp+6]
    call far CallWindowProc
    pop bp
    retf 10
segment _DATA public class=DATA use16
wc: dw 3
    dw wndproc, 0
    dw 0,2,0,0,0,16
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
position: dw 0,0,0,0,0,0,3
size_kind: dw 0xffff
local_block: dw 0
timer_id: dw 0
message_button: dw 0
question: db "Choose No to continue the test.",0
question_title: db "Shared modal message",0
scroll: dw 0
scroll_events: dw 0
scroll_class: db "ScrollBar",0
button: dw 0
button_proc: dd 0
button_text: times 16 db 0
clicked: dw 0
button_class: db "Button",0
button_title: db "button",0
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

list_class: db "ListBox",0
list_empty: db 0
list_text: db "Apple",0
list_buffer: times 8 db 0
list_hwnd: dw 0
clock_sample: dw 0
clock_start: dw 0
file_path: db "C:\FILETEST.DAT",0
file_missing: db "C:\ABSENT.DAT",0
file_payload: db "hello",0
file_buffer: times 8 db 0
file_handle: dw 0
kernel_name: db "KERNEL",0
version_name: db "GetVersion",0
lz_name: db "LZEXPAND.DLL",0
lz_copy_name: db "LZCopy",0
lz_module: dw 0
installer_proc: dd 0
lz_source: dw 0
lz_dest: dw 0
temp_unique: dw 0
ini_section: db "Installer",0
ini_key: db "Target",0
ini_default: db "WRONG",0
ini_path: db "C:\INSTALL.INI",0
ini_result: times 32 db 0
tiny_rect: dw 0,0,1,1
test_global: dw 0
test_atom: dw 0
atom_name: db "Installer",0
atom_lower: db "installer",0
atom_buffer: times 32 db 0
temp_prefix: db "TEST",0
temp_one: times 144 db 0
temp_two: times 144 db 0
compressed: db "SZDD",0x88,0xf0,0x27,0x33,'A',0
    dd 9
    db 7,'a','b','c',0xf0,0xf3
compressed_end:
expanded: times 16 db 0
installer_error: db "Installer services failed",0
pm_directory: db "PMTEST",0
pm_relative_file: db "ROUND.DAT",0
pm_absolute_file: db "C:\PMTEST\ROUND.DAT",0
pm_root: db "C:\",0
pm_error: db "PMDOS interoperability failed",0
format_text: db "%d %s %04X %ld",0
format_args: dw -2,file_payload,0,0x2a
    dd 70
format_buffer: times 64 db 0
file_error_1: db "file step 1",0
file_error_2: db "file step 2",0
file_error_3: db "file step 3",0
file_error_4: db "file step 4",0
file_error_5: db "file step 5",0
file_error_6: db "file step 6",0
file_error_7: db "file step 7",0
file_error_8: db "file step 8",0
file_error_9: db "file step 9",0
file_error_10: db "file step 10",0
file_error_11: db "file step 11",0
file_error_12: db "file step 12",0
file_error_13: db "file step 13",0
file_error_14: db "file step 14",0
file_error_15: db "file step 15",0

cursor_point: dw 0,0

segment STACK stack class=STACK use16
    resb 8192
group DGROUP _DATA STACK
