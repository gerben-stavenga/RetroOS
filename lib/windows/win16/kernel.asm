bits 16
segment _TEXT public class=CODE use16
%include "lib/windows/win16/bridge.inc"

%macro gate 1
global %1
%1: int 0x83
%endmacro

gate FatalExit
gate GetVersion
gate LocalInit
gate LocalAlloc
gate LocalReAlloc
gate LocalFree
gate LocalLock
gate LocalUnlock
gate LocalSize
gate GlobalAlloc
gate GlobalReAlloc
gate GlobalFree
gate GlobalLock
gate GlobalUnlock
gate GlobalSize
gate LockSegment
gate UnlockSegment
gate GlobalCompact
gate WaitEvent
gate GetModuleHandle
gate GetModuleUsage
gate GetModuleFileName
gate GetProcAddress
gate MakeProcInstance
gate FreeProcInstance
bridge GetProfileString, 2058, 18
gate FindResource
gate LoadResource
gate LockResource
gate FreeResource
gate OpenFile
bridge _lclose, 2081, 2
bridge _lread, 2082, 8
bridge _lcreat, 2083, 6
bridge _llseek, 2084, 8
bridge _lopen, 2085, 6
bridge _lwrite, 2086, 8
gate lstrcpy
gate lstrcat
gate lstrlen
gate InitTask
; Loader policy runs in the kernel; LibMain executes here on the caller's
; guest stack. All suspended state survives nested LoadLibrary calls naturally.
gate RetroLoadLibrary
gate RetroNextInitializer

global LoadLibrary
LoadLibrary:
    push bp
    mov bp, sp
    pushfd
    pushad
    push ds
    push es
    push fs
    push gs
    push word [ss:bp+8]
    push word [ss:bp+6]
    push cs
    call RetroLoadLibrary
    cmp ax,32
    jb .done
    call initialize_modules
.done:
    mov [ss:bp-8],ax
    pop gs
    pop fs
    pop es
    pop ds
    popad
    popfd
    pop bp
    retf 4

global RetroInitLibraries
RetroInitLibraries:
    pushfd
    pushad
    push ds
    push es
    push fs
    push gs
    xor ax,ax
    call initialize_modules
    test ax,ax
    jz .done
    push ax
    push cs
    call FatalExit
.done:
    pop gs
    pop fs
    pop es
    pop ds
    popad
    popfd
    retf

; AX=root handle (zero for process startup). The 12-byte initializer record,
; root handle and acknowledgement are local to this guest stack frame.
initialize_modules:
    push bp
    mov bp,sp
    sub sp,16
    mov [ss:bp-4],ax
    mov word [ss:bp-2],0
    mov ax,1
.next:
    push word [ss:bp-4]
    push word [ss:bp-2]
    push ax
    push ss
    lea ax,[bp-16]
    push ax
    push cs
    call RetroNextInitializer
    test ax,ax
    jz .ready
    cmp ax,0xffff
    jne .return
    mov ax,[ss:bp-6]
    mov [ss:bp-2],ax
    mov ax,[ss:bp-12]
    mov ds,ax
    mov es,ax
    mov cx,[ss:bp-10]
    mov di,[ss:bp-8]
    xor bx,bx
    xor si,si
    push bp
    call far [ss:bp-16]
    pop bp
    jmp .next
.ready:
    mov ax,[ss:bp-4]
.return:
    mov sp,bp
    pop bp
    ret
gate FreeLibrary
bridge GetTempFileName, 2097, 12
gate DOS3Call
gate SetErrorMode
gate OutputDebugString
gate LocalShrink
bridge GetPrivateProfileInt, 2127, 14
bridge GetPrivateProfileString, 2128, 22
gate WritePrivateProfileString
gate GetDOSEnvironment
gate GetWinFlags
bridge GetSystemDirectory, 2135, 6
gate GetDriveType
gate FatalAppExit
gate IsDBCSLeadByte

bridge WinExec, 2166, 6

bridge GetWindowsDirectory, 2134, 6

gate GlobalHandle
gate GetFreeSpace
gate AllocCStoDSAlias
gate AllocSelector
gate FreeSelector
gate PrestoChangoSelector

bridge GetProfileInt, 2057, 10
gate GetHeapSpaces

bridge hmemcpy, 2348, 12
bridge _hread, 2349, 10
bridge _hwrite, 2350, 10
