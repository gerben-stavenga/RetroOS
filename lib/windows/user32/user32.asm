bits 32

section .text

%macro gate 1
global %1
%1: int 0x83
%endmacro

gate AdjustWindowRect
gate BeginPaint
gate CharUpperA
gate CheckMenuItem
gate DestroyIcon
gate DialogBoxParamW
gate DrawEdge
gate EndDialog
gate EndPaint
gate FillRect
gate GetDC
gate GetDlgItemInt
gate GetDlgItemTextW
gate GetMenuItemRect
gate GetSysColorBrush
gate GetSystemMetrics
gate InvalidateRect
gate LoadAcceleratorsW
gate LoadCursorW
gate LoadIconW
gate LoadMenuW
gate LoadStringW
gate MessageBoxW
gate RetroWndProcReturn
gate ReleaseCapture
gate ReleaseDC
gate SetCapture
gate SetDlgItemInt
gate SetDlgItemTextW
gate SetMenu
gate TranslateAcceleratorW
gate TranslateMessage
gate UpdateWindow

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
