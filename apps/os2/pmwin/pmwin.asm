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
WinGetMsg:          int 0x82
WinDispatchMsg:     int 0x82
WinDestroyWindow:   int 0x82
WinDestroyMsgQueue: int 0x82
WinTerminate:       int 0x82
