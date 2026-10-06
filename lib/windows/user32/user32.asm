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
gate CreateWindowExW
gate DefWindowProcW
gate DestroyIcon
gate DialogBoxParamW
gate DispatchMessageW
gate DrawEdge
gate EndDialog
gate EndPaint
gate FillRect
gate GetClientRect
gate GetDC
gate GetDlgItem
gate GetDlgItemInt
gate GetDlgItemTextW
gate GetMenuItemRect
gate GetMessageW
gate GetSysColorBrush
gate GetSystemMetrics
gate InflateRect
gate InvalidateRect
gate KillTimer
gate LoadAcceleratorsW
gate LoadCursorW
gate LoadIconW
gate LoadMenuW
gate LoadStringW
gate MapWindowPoints
gate MessageBoxW
gate MoveWindow
gate OffsetRect
gate PeekMessageW
gate PostMessageW
gate PostQuitMessage
gate PtInRect
gate RegisterClassW
gate RetroWndProcReturn
gate ReleaseCapture
gate ReleaseDC
gate SendMessageW
gate SetCapture
gate SetDlgItemInt
gate SetDlgItemTextW
gate SetMenu
gate SetRect
gate SetTimer
gate ShowWindow
gate TranslateAcceleratorW
gate TranslateMessage
gate UpdateWindow
