; Common-dialog callers can distinguish unavailable UI from user cancellation.
bits 16
segment _TEXT public class=CODE use16
global GetOpenFileName, GetSaveFileName, CommDlgExtendedError
GetOpenFileName:
GetSaveFileName:
    xor ax, ax
    retf 4
CommDlgExtendedError:
    mov ax, 2                    ; CDERR_INITIALIZATION
    xor dx, dx
    retf
