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

bridge GetCurrentTask, 2036, 0
gate GlobalHandleNoRIP

global DebugBreak
DebugBreak:
    int3
    retf

; Pointer probes use descriptor permissions and limits without touching memory.
; Huge pointers advance by AHINCR (8) at each 64 KiB boundary.
%macro pointer_probe 4
 global %1
%1:
    push bp
    mov bp,sp
    push ebx
    push ecx
    push edx
    push esi
    push edi
    mov bl,%3                 ; 0=read, 1=write, 2=code
    mov bh,%4                 ; huge range
%if %2 = 8
    mov ecx,[ss:bp+6]
%elif %2 = 6
    movzx ecx,word [ss:bp+6]
%else
    mov ecx,1
%endif
    movzx eax,word [ss:bp+%2+2]
    mov dx,[ss:bp+%2+4]
    call probe_range
    pop edi
    pop esi
    pop edx
    pop ecx
    pop ebx
    pop bp
    retf %2
%endmacro
pointer_probe IsBadReadPtr, 6, 0, 0
pointer_probe IsBadWritePtr, 6, 1, 0
pointer_probe IsBadCodePtr, 4, 2, 0
pointer_probe IsBadHugeReadPtr, 8, 0, 1
pointer_probe IsBadHugeWritePtr, 8, 1, 1

probe_range:
    test ecx,ecx
    jz .good
.next:
    lar esi,dx
    jnz .bad
    test esi,0x8000           ; present
    jz .bad
    test esi,0x1000           ; application segment
    jz .bad
    cmp bl,2
    je .code
    cmp bl,1
    je .write
    verr dx
    jnz .bad
    jmp .limit
.write:
    verw dx
    jnz .bad
    jmp .limit
.code:
    test esi,0x0800
    jz .bad
.limit:
    lsl edi,dx
    jnz .bad
    ; Expand-down data segments have a lower exclusive limit.
    test esi,0x0800
    jnz .normal
    test esi,0x0400
    jz .normal
    cmp eax,edi
    jbe .bad
    mov edi,0xffff
    test esi,0x400000
    jz .normal
    mov edi,0xffffffff
.normal:
    test bh,bh
    jz .bounded
    cmp edi,0xffff
    jbe .bounded
    mov edi,0xffff
.bounded:
    cmp eax,edi
    ja .bad
    sub edi,eax
    dec ecx
    cmp ecx,edi
    jbe .good
    inc ecx
    test bh,bh
    jz .bad
    ; A short final selector cannot be crossed to an unrelated allocation.
    add edi,eax
    cmp edi,0xffff
    jne .bad
    mov esi,0x10000
    sub esi,eax
    sub ecx,esi
    add dx,8
    jc .bad
    xor eax,eax
    jmp .next
.good:
    xor ax,ax
    ret
.bad:
    mov ax,1
    ret
