bits 32

section .text

%macro gate 1
global %1
%1: int 0x83
%endmacro

gate DrawEdge
global _FillRect@12
_FillRect@12:
gate FillRect
global _GetSysColorBrush@4
_GetSysColorBrush@4:
gate GetSysColorBrush
global _GetSystemMetrics@4
_GetSystemMetrics@4:
gate GetSystemMetrics
gate RetroWndProcReturn

; Private kernel operations return normally to this guest DLL. All suspended
; window-procedure calls live on the guest stack, including nested creation.
global _RetroReleaseWindow@4
_RetroReleaseWindow@4:
gate RetroReleaseWindow

global _RetroSurfaceCreate@20
_RetroSurfaceCreate@20:
gate RetroSurfaceCreate
global _RetroSurfaceUpdate@28
_RetroSurfaceUpdate@28:
gate RetroSurfaceUpdate

global _RetroReadEvent@8
_RetroReadEvent@8:
gate RetroReadEvent

extern _wvsprintfA@12
global wsprintfA
wsprintfA:
    lea eax, [esp+12]
    push eax
    push dword [esp+12]
    push dword [esp+12]
    call _wvsprintfA@12
    ret

extern _wvsprintfW@12
global wsprintfW
wsprintfW:
    lea eax, [esp+12]
    push eax
    push dword [esp+12]
    push dword [esp+12]
    call _wvsprintfW@12
    ret

global _GetKeyState@4
_GetKeyState@4:
gate GetKeyState

global _RetroSurfaceDC@24
_RetroSurfaceDC@24:
gate RetroSurfaceDC

global _RetroInvalidateWindow@12
_RetroInvalidateWindow@12:
gate RetroInvalidateWindow

global _RetroValidateWindow@4
_RetroValidateWindow@4:
gate RetroValidateWindow

global _RetroEndPaint@8
_RetroEndPaint@8:
gate RetroEndPaint

; Win16 bridge. Contexts and continuations reside entirely in guest memory.
; Config: flat DS, TEB selector, stack cursor, active frame, selector table,
; callback return far pointer. One NE task; recursive callbacks nest normally.
section .data align=4
global Retro16Config, _Retro16Config
_Retro16Config:
Retro16Config:
    times 11 dd 0
retro16_jump: dd 0
    dw 0
retro16_stack: dd 0
    dw 0

section .text
extern _Retro16Dispatch@12
global Retro16Enter
Retro16Enter:
    cld
    ; Leave room for the Rust adapter before accepting another nested entry.
    mov ecx, [cs:Retro16Config+8]
    sub ecx, 8192
    cmp ecx, [cs:Retro16Config+28]
    jb retro16_overflow
    mov bx, [cs:Retro16Config]
    mov ds, bx
    mov es, bx
    mov bx, [Retro16Config+4]
    mov fs, bx
    mov ebx, eax
    shr ebx, 3
    mov ecx, [Retro16Config+16]
    add esi, [ecx+ebx*8]       ; linear address of saved 16-bit frame
    mov bx, [Retro16Config]
    mov ss, bx
    mov esp, [Retro16Config+8]
    push edi                    ; 16-bit return offset
    push edx                    ; 16-bit CS
    push eax                    ; 16-bit SS
    push esi                    ; saved frame, linear
    push dword [Retro16Config+12]
    mov [Retro16Config+12], esp
    mov ebp, esp
    and esp, -16
    sub esp, 4
    push ebp
    lea ecx, [esi+52]            ; Pascal arguments after far return address
    push ecx
    movzx ecx, word [esi+46]
    push ecx
    call _Retro16Dispatch@12
    mov esp, ebp
    mov esi, [esp+4]
    mov [esi+36], eax
    shr eax, 16
    mov [esi+28], eax            ; Win16 LONG result is DX:AX
    pop dword [Retro16Config+12]
    add esp, 4
    pop eax                     ; old SS
    pop edx                     ; old CS
    pop edi                     ; bridge_return IP
    mov [retro16_jump], edi
    mov [retro16_jump+4], dx
    mov ebx, eax
    shr ebx, 3
    mov ecx, [Retro16Config+16]
    sub esi, [ecx+ebx*8]
    mov [retro16_stack], esi
    mov [retro16_stack+4], ax
    lss esp, [retro16_stack]
    jmp far [cs:retro16_jump]

retro16_overflow:
    ud2                         ; terminate the guest instead of overwriting a frame

; u32 __stdcall Retro16Call(farproc, arguments, size, scratch_size)
; Rust prepares a bounded temporary area below the suspended Win16 frame.
global _Retro16Call@16
_Retro16Call@16:
    push ebp
    push ebx
    push esi
    push edi
    mov ebp, esp
    mov eax, [ebp+20]
    movzx edx, ax
    shr eax, 16
    mov [retro16_jump], edx
    mov [retro16_jump+4], ax
    mov ebx, [Retro16Config+12]
    mov edi, [ebx+4]
    sub edi, [ebp+32]
    mov ecx, [ebp+28]
    sub edi, ecx
    mov esi, [ebp+24]
    rep movsb
    mov edi, [ebx+4]
    sub edi, [ebp+32]
    sub edi, [ebp+28]
    sub edi, 4
    mov eax, [Retro16Config+20]
    mov [edi], eax              ; IP:CS return into the NE DLL
    mov eax, [ebx+8]
    mov edx, eax
    shr eax, 3
    mov ecx, [Retro16Config+16]
    sub edi, [ecx+eax*8]
    mov [retro16_stack], edi
    mov [retro16_stack+4], dx
    push dword [Retro16Config+8]
    mov [Retro16Config+8], esp  ; nested entry starts below this call frame
    mov esi, [ebx+4]
    mov ax, [esi+6]             ; original Win16 DS (MakeProcInstance may change it)
    mov es, ax
    mov ds, ax
    lss esp, [cs:retro16_stack]
    jmp far [cs:retro16_jump]

global Retro16Return
Retro16Return:
    cld
    movzx eax, ax
    shl edx, 16
    or eax, edx
    mov bx, [cs:Retro16Config]
    mov ds, bx
    mov es, bx
    mov ss, bx
    mov esp, [Retro16Config+8]
    pop dword [Retro16Config+8]
    mov bx, [Retro16Config+4]
    mov fs, bx
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret 16

global _RetroPointerVisible@4
_RetroPointerVisible@4:
gate RetroPointerVisible
global _RetroPointerPosition@8
_RetroPointerPosition@8:
gate RetroPointerPosition
