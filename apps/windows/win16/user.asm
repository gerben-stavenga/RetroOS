bits 16
segment _TEXT public class=CODE use16

%macro gate 1
global %1
%1: int 0x83
%endmacro

gate MessageBox
gate InitApp
gate PostQuitMessage
gate SetTimer
gate KillTimer
gate GetCurrentTime
gate SetCapture
gate ReleaseCapture
gate ClientToScreen
gate IsIconic
gate BeginPaint
gate EndPaint
gate CreateWindow
gate ShowWindow
gate BringWindowToTop
gate FindWindow
gate DestroyWindow
gate MoveWindow
gate RegisterClass
gate GetDC
gate ReleaseDC
gate SetRect
gate PtInRect
gate DialogBox
gate EndDialog
gate SetDlgItemText
gate GetDlgItemText
gate SetDlgItemInt
gate GetDlgItemInt
gate DefWindowProc
gate GetMessage
gate PeekMessage
gate PostMessage
gate SendMessage
gate TranslateMessage
gate DispatchMessage
gate UpdateWindow
gate InvalidateRect
gate LoadMenu
gate CheckMenuItem
gate EnableMenuItem
gate SetMenu
gate WinHelp
gate LoadCursor
gate LoadIcon
gate LoadString
gate LoadAccelerators
gate TranslateAccelerator
gate GetSystemMetrics
gate GetDesktopWindow
gate GetLastActivePopup
gate wsprintf
gate RetroWndProcReturn
