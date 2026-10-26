bits 32

section .text

%macro gate 1
global %1
%1: int 0x83
%endmacro

gate AdjustWindowRect
gate DrawEdge
global _FillRect@12
_FillRect@12:
gate FillRect
gate GetDlgItemInt
gate GetMenuItemRect
gate GetSysColorBrush
gate GetSystemMetrics
gate MessageBoxW
gate RetroWndProcReturn
gate SetDlgItemInt
gate TranslateMessage

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

global _RetroSurfaceDC@8
_RetroSurfaceDC@8:
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
