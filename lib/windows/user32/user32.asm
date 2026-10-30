bits 32

section .text

%macro gate 1
global %1
%1: int 0x83
%endmacro

gate DrawEdge
global _GetSysColorBrush@4
_GetSysColorBrush@4:
gate GetSysColorBrush
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
global _RetroSurfaceOrder@8
_RetroSurfaceOrder@8:
gate RetroSurfaceOrder

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

; Win16 bridge. Each thread's WOW32Reserved (TEB+0xc0) points at
; {cursor, active_frame, lower_bound, jump_offset, jump_selector,
;  stack_offset, stack_selector}. Contexts and callbacks are guest-owned.
section .data align=4
global Retro16Config, _Retro16Config
_Retro16Config:
Retro16Config:
    times 12 dd 0
retro16_main_context: times 7 dd 0

section .text
extern _Retro16Dispatch@12
global _Retro16Context@0
_Retro16Context@0:
    mov eax,[fs:0xc0]
    ret

global _Retro16SwapContext@4
_Retro16SwapContext@4:
    mov eax,[fs:0xc0]
    mov ecx,[esp+4]
    mov [fs:0xc0],ecx
    ret 4

global Retro16Enter
Retro16Enter:
    cld
    mov bx,[cs:Retro16Config]
    mov ds,bx
    mov es,bx
    mov bx,[Retro16Config+4]
    mov fs,bx
    mov ebx,[fs:0xc0]
    test ebx,ebx
    jnz .context
    mov ebx,retro16_main_context
    mov ecx,[Retro16Config+8]
    mov [ebx],ecx
    mov ecx,[Retro16Config+28]
    mov [ebx+8],ecx
    mov [fs:0xc0],ebx
.context:
    mov ecx,[ebx]
    sub ecx,8192
    cmp ecx,[ebx+8]
    jb retro16_overflow
    mov ecx,eax
    shr ecx,3
    mov ebx,[Retro16Config+16]
    add esi,[ebx+ecx*8]
    mov bx,[Retro16Config]
    mov ss,bx
    mov ebx,[fs:0xc0]
    mov esp,[ebx]
    push edi
    push edx
    push eax
    push esi
    push dword [ebx+4]
    mov [ebx+4],esp
    mov ebp,esp
    and esp,-16
    sub esp,4
    push ebp
    lea ecx,[esi+52]
    push ecx
    movzx ecx,word [esi+46]
    push ecx
    call _Retro16Dispatch@12
    mov esp,ebp
    mov esi,[esp+4]
    mov [esi+36],eax
    shr eax,16
    mov [esi+28],eax
    mov ebx,[fs:0xc0]
    pop dword [ebx+4]
    add esp,4
    pop eax
    pop edx
    pop edi
    mov [ebx+12],edi
    mov [ebx+16],dx
    mov ecx,eax
    shr ecx,3
    mov edx,[Retro16Config+16]
    sub esi,[edx+ecx*8]
    mov [ebx+20],esi
    mov [ebx+24],ax
    lss esp,[ebx+20]
    jmp far [cs:ebx+12]

retro16_overflow:
    ud2

; u32 __stdcall Retro16Call(farproc, arguments, size, scratch_size)
global _Retro16Call@16
_Retro16Call@16:
    push ebp
    push ebx
    push esi
    push edi
    mov ebp,esp
    mov ecx,[fs:0xc0]
    mov eax,[ebp+20]
    movzx edx,ax
    shr eax,16
    mov [ecx+12],edx
    mov [ecx+16],ax
    mov ebx,[ecx+4]
    mov edi,[ebx+4]
    sub edi,[ebp+32]
    mov ecx,[ebp+28]
    sub edi,ecx
    mov esi,[ebp+24]
    rep movsb
    mov edi,[ebx+4]
    sub edi,[ebp+32]
    sub edi,[ebp+28]
    sub edi,4
    mov eax,[Retro16Config+20]
    mov [edi],eax
    mov eax,[ebx+8]
    mov edx,eax
    shr eax,3
    mov ecx,[Retro16Config+16]
    sub edi,[ecx+eax*8]
    mov ecx,[fs:0xc0]
    mov [ecx+20],edi
    mov [ecx+24],dx
    push dword [ecx]
    mov [ecx],esp
    mov esi,[ebx+4]
    mov ax,[esi+6]
    mov es,ax
    mov ds,ax
    lss esp,[cs:ecx+20]
    jmp far [cs:ecx+12]

global Retro16Return
Retro16Return:
    cld
    movzx eax,ax
    shl edx,16
    or eax,edx
    mov bx,[cs:Retro16Config]
    mov ds,bx
    mov es,bx
    mov ss,bx
    mov bx,[Retro16Config+4]
    mov fs,bx
    mov ebx,[fs:0xc0]
    mov esp,[ebx]
    pop dword [ebx]
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
