bits 16
segment _TEXT public class=CODE use16
%include "lib/windows/win16/bridge.inc"

%macro gate 1
global %1
%1: int 0x83
%endmacro




bridge MessageBox, 1, 12
bridge InitApp, 5, 2
bridge PostQuitMessage, 6, 2
bridge SetTimer, 10, 10
bridge KillTimer, 12, 4
bridge GetCurrentTime, 15, 0
gate ClipCursor
bridge GetCursorPos, 17, 4
bridge SetCapture, 18, 2
bridge ReleaseCapture, 19, 0
bridge SetFocus, 22, 2
bridge GetFocus, 23, 0
bridge RemoveProp, 24, 6
bridge GetProp, 25, 6
bridge SetProp, 26, 8
bridge ClientToScreen, 28, 6
bridge ScreenToClient, 29, 6
bridge IsIconic, 31, 2
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
bridge ScrollWindow, 61, 14
bridge SetScrollPos, 62, 8
bridge SetScrollRange, 64, 10
bridge GetDC, 66, 2
bridge ReleaseDC, 68, 4
bridge SetCursor, 69, 2
bridge SetCursorPos, 70, 4
bridge ShowCursor, 71, 2
bridge SetRect, 72, 12
bridge CopyRect, 74, 8
bridge PtInRect, 76, 8
bridge OffsetRect, 77, 8
bridge InflateRect, 78, 8
bridge IntersectRect, 79, 12
bridge FillRect, 81, 8
bridge FrameRect, 83, 8
bridge DrawIcon, 84, 8
bridge DrawText, 85, 14
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
bridge GetKeyState, 106, 2
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
bridge ChangeMenu, 153, 12
bridge CheckMenuItem, 154, 6
bridge EnableMenuItem, 155, 6
bridge GetSystemMenu, 156, 4
bridge GetMenu, 157, 2
bridge SetMenu, 158, 4
bridge GetSubMenu, 159, 4
bridge DrawMenuBar, 160, 2
gate WinHelp
bridge LoadCursor, 173, 6
bridge LoadIcon, 174, 6
bridge LoadBitmap, 175, 6
gate LoadString
gate LoadAccelerators
gate TranslateAccelerator
bridge GetSystemMetrics, 179, 2
gate GetSysColor
gate GrayString
gate GetSysModalWindow
gate ChildWindowFromPoint
bridge TabbedTextOut, 196, 20
gate GetTopWindow
bridge SetWindowPos, 232, 14
bridge GetCapture, 236, 0
gate DialogBoxIndirectParam
bridge CreateDialogIndirectParam, 242, 16
bridge EqualRect, 244, 8
gate GetAsyncKeyState
bridge GetDlgCtrlID, 277, 2
bridge SelectPalette, 282, 6
bridge RealizePalette, 283, 2
bridge GetDesktopWindow, 286, 0
gate GetLastActivePopup
gate CreateIcon
bridge InsertMenu, 410, 12
bridge AppendMenu, 411, 10
bridge RemoveMenu, 412, 6
bridge DeleteMenu, 413, 6
bridge ModifyMenu, 414, 12
gate wsprintf
gate lstrcmp
bridge AnsiUpper, 431, 4
bridge AnsiLower, 432, 4
bridge DestroyIcon, 457, 2
bridge DestroyCursor, 458, 2
gate DrawFocusRect
gate lstrcmpi
gate AnsiNext
gate WNetGetConnection

bridge wvsprintf, 421, 12

bridge GlobalAddAtom, 268, 4
bridge GlobalDeleteAtom, 269, 2
bridge GlobalFindAtom, 270, 4
bridge GlobalGetAtomName, 271, 8

bridge GetTickCount, 13, 0
bridge GetWindowTextLength, 38, 2
bridge IsChild, 48, 4
bridge IsWindowVisible, 49, 2
bridge IsDialogMessage, 90, 6
bridge WaitMessage, 112, 0
bridge GetNextDlgTabItem, 228, 6
bridge DialogBoxParam, 239, 16
bridge CreateDialogParam, 241, 16
bridge GetMenuState, 250, 6
bridge IsZoomed, 272, 2
bridge GetFreeSystemResources, 284, 2
bridge DefDlgProc, 308, 10
bridge GetClassInfo, 404, 10
bridge CreateWindowEx, 452, 34

bridge DefMDIChildProc, 447, 10
bridge TranslateMDISysAccel, 451, 6

; Real callable/readable far procedures for shared 32-bit control classes.
; Win16 frameworks may inspect a WNDPROC before forwarding through it.
align 16
global RetroNativeProcedures
RetroNativeProcedures:
%assign native_index 0
%rep 256
    push word (20000 + native_index)
    call bridge_enter
    add sp, 2
    retf 10
    align 16
%assign native_index native_index + 1
%endrep

bridge GetScrollRange, 65, 12
bridge CreateDialog, 89, 12
bridge CreateDialogIndirect, 219, 12
bridge GetDialogBaseUnits, 243, 0

bridge CreateCaret, 163, 8
bridge DestroyCaret, 164, 0
bridge SetCaretPos, 165, 4
bridge HideCaret, 166, 2
bridge ShowCaret, 167, 2
bridge SetCaretBlinkTime, 168, 2
bridge GetCaretBlinkTime, 169, 0
bridge GetCaretPos, 183, 4

bridge EnumWindows, 54, 8
bridge EnumChildWindows, 55, 10
bridge GetWindowTask, 224, 2
bridge EnumTaskWindows, 225, 10

bridge InSendMessage, 251, 0
bridge SetMessageQueue, 266, 2

bridge MapWindowPoints, 258, 10

bridge GetClassName, 58, 8
bridge GetScrollPos, 63, 4
bridge SetRectEmpty, 73, 4
bridge IsRectEmpty, 75, 4
bridge UnionRect, 80, 12
bridge GetClassWord, 129, 4
bridge GetNextWindow, 230, 4
bridge GetWindow, 262, 4
bridge GetMenuItemCount, 263, 2
bridge GetMenuItemID, 264, 4
bridge UnregisterClass, 403, 6
bridge CreatePopupMenu, 415, 0

bridge ShowScrollBar, 267, 6

bridge TrackPopupMenu, 416, 16
