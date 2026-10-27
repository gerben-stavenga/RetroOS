bits 16
segment _TEXT public class=CODE use16
%include "lib/windows/win16/bridge.inc"

%macro gate 1
global %1
%1: int 0x83
%endmacro




gate MessageBox
bridge InitApp, 5, 2
bridge PostQuitMessage, 6, 2
bridge SetTimer, 10, 10
bridge KillTimer, 12, 4
bridge GetCurrentTime, 15, 0
gate ClipCursor
gate GetCursorPos
bridge SetCapture, 18, 2
bridge ReleaseCapture, 19, 0
bridge SetFocus, 22, 2
bridge GetFocus, 23, 0
gate RemoveProp
gate GetProp
gate SetProp
gate ClientToScreen
gate ScreenToClient
gate IsIconic
bridge GetWindowRect, 32, 6
bridge GetClientRect, 33, 6
bridge EnableWindow, 34, 4
bridge IsWindowEnabled, 35, 2
bridge GetWindowText, 36, 8
bridge SetWindowText, 37, 6
bridge BeginPaint, 39, 6
bridge EndPaint, 40, 6
bridge CreateWindow, 41, 30
bridge ShowWindow, 42, 4
gate BringWindowToTop
bridge GetParent, 46, 2
bridge IsWindow, 47, 2
gate FindWindow
bridge DestroyWindow, 53, 2
bridge MoveWindow, 56, 12
bridge RegisterClass, 57, 4
bridge GetActiveWindow, 60, 0
gate ScrollWindow
bridge SetScrollPos, 62, 8
bridge SetScrollRange, 64, 10
bridge GetDC, 66, 2
bridge ReleaseDC, 68, 4
gate SetCursor
gate SetCursorPos
gate ShowCursor
bridge SetRect, 72, 12
bridge CopyRect, 74, 8
bridge PtInRect, 76, 8
bridge OffsetRect, 77, 8
bridge InflateRect, 78, 8
bridge IntersectRect, 79, 12
bridge FillRect, 81, 8
gate FrameRect
gate DrawIcon
gate DrawText
bridge DialogBox, 87, 12
bridge EndDialog, 88, 4
bridge GetDlgItem, 91, 4
bridge SetDlgItemText, 92, 8
bridge GetDlgItemText, 93, 10
bridge SetDlgItemInt, 94, 8
bridge GetDlgItemInt, 95, 10
bridge CheckRadioButton, 96, 8
bridge CheckDlgButton, 97, 6
bridge IsDlgButtonChecked, 98, 4
gate DlgDirList
bridge SendDlgItemMessage, 101, 12
gate MessageBeep
gate GetKeyState
bridge DefWindowProc, 107, 10
bridge GetMessage, 108, 10
bridge PeekMessage, 109, 12
bridge PostMessage, 110, 10
bridge SendMessage, 111, 10
bridge TranslateMessage, 113, 4
bridge DispatchMessage, 114, 4
gate RegisterWindowMessage
bridge CallWindowProc, 122, 14
bridge UpdateWindow, 124, 2
bridge InvalidateRect, 125, 8
bridge ValidateRect, 127, 6
gate GetClassLong
bridge GetWindowWord, 133, 4
bridge SetWindowWord, 134, 6
bridge GetWindowLong, 135, 4
bridge SetWindowLong, 136, 8
bridge LoadMenu, 150, 6
bridge CreateMenu, 151, 0
bridge DestroyMenu, 152, 2
gate ChangeMenu
bridge CheckMenuItem, 154, 6
bridge EnableMenuItem, 155, 6
bridge GetSystemMenu, 156, 4
bridge GetMenu, 157, 2
bridge SetMenu, 158, 4
bridge GetSubMenu, 159, 4
bridge DrawMenuBar, 160, 2
gate WinHelp
gate LoadCursor
gate LoadIcon
bridge LoadBitmap, 175, 6
gate LoadString
gate LoadAccelerators
gate TranslateAccelerator
bridge GetSystemMetrics, 179, 2
gate GetSysColor
gate GrayString
gate GetSysModalWindow
gate ChildWindowFromPoint
gate TabbedTextOut
gate GetTopWindow
gate SetWindowPos
bridge GetCapture, 236, 0
gate DialogBoxIndirectParam
bridge CreateDialogIndirectParam, 242, 16
bridge EqualRect, 244, 8
gate GetAsyncKeyState
bridge GetDlgCtrlID, 277, 2
gate SelectPalette
gate RealizePalette
gate GetDesktopWindow
gate GetLastActivePopup
gate CreateIcon
bridge InsertMenu, 410, 12
bridge AppendMenu, 411, 10
bridge RemoveMenu, 412, 6
bridge DeleteMenu, 413, 6
bridge ModifyMenu, 414, 12
gate wsprintf
gate lstrcmp
gate AnsiUpper
gate AnsiLower
gate DestroyIcon
gate DrawFocusRect
gate lstrcmpi
gate AnsiNext
gate WNetGetConnection
