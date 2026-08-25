bits 32

section _TEXT use32 class=CODE

global WinInitialize
global WinCreateMsgQueue
global WinCreateWindow
global WinShowWindow
global WinGetPS
global WinReleasePS
global WinFillRect
global WinPostQueueMsg
global WinGetMsg
global WinDispatchMsg
global WinDestroyWindow
global WinDestroyMsgQueue
global WinTerminate
global WinBeginPaint
global WinDismissDlg
global WinDrawBitmap
global WinDrawBorder
global WinEndPaint
global WinInvalidateRect
global WinLoadString
global WinMessageBox
global WinPtInRect
global WinQueryDlgItemText
global WinQuerySysValue
global WinQueryWindow
global WinQueryWindowPos
global WinQueryWindowRect
global WinSetDlgItemText
global WinSetWindowPos
global WinStartTimer
global WinStopTimer
global WinWindowFromID
global WinSendDlgItemMsg
global WinCreateStdWindow
global WinDefDlgProc
global WinDefWindowProc
global WinSendMsg
global WinDlgBox
global WinRegisterClass
global RetroWndProcReturn

; Presentation Manager is a personality protocol, just like DOSCALLS.  The
; instruction following each private gate identifies the imported PM API;
; the kernel completes the caller's _System call frame.
WinInitialize:      int 0x82
WinCreateMsgQueue:  int 0x82
WinCreateWindow:    int 0x82
WinShowWindow:      int 0x82
WinGetPS:           int 0x82
WinReleasePS:       int 0x82
WinFillRect:        int 0x82
WinPostQueueMsg:    int 0x82
; WinGetMsg is the one PM call that waits.  If the kernel leaves us at the
; instruction following the gate, park the guest until the event loop runs us
; again, then retry without unwinding the application's call frame.  When a
; message is available the kernel completes the call directly, so this tail is
; never executed.
WinGetMsg:          int 0x82
                    hlt
                    jmp WinGetMsg
WinDispatchMsg:     int 0x82
WinDestroyWindow:   int 0x82
WinDestroyMsgQueue: int 0x82
WinTerminate:       int 0x82
WinBeginPaint:      int 0x82
WinDismissDlg:      int 0x82
WinDrawBitmap:      int 0x82
WinDrawBorder:      int 0x82
WinEndPaint:        int 0x82
WinInvalidateRect:  int 0x82
WinLoadString:      int 0x82
WinMessageBox:      int 0x82
WinPtInRect:        int 0x82
WinQueryDlgItemText:int 0x82
WinQuerySysValue:   int 0x82
WinQueryWindow:     int 0x82
WinQueryWindowPos:  int 0x82
WinQueryWindowRect: int 0x82
WinSetDlgItemText:  int 0x82
WinSetWindowPos:    int 0x82
WinStartTimer:      int 0x82
WinStopTimer:       int 0x82
WinWindowFromID:    int 0x82
WinSendDlgItemMsg:  int 0x82
WinCreateStdWindow: int 0x82
WinDefDlgProc:      int 0x82
WinDefWindowProc:   int 0x82
WinSendMsg:         int 0x82
WinDlgBox:          int 0x82
WinRegisterClass:   int 0x82
RetroWndProcReturn: int 0x82
