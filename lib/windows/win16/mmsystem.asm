; No Windows multimedia device is registered yet. Report failure to optional
; callers instead of claiming that a sound or MCI command was played.
bits 16
segment _TEXT public class=CODE use16
global sndPlaySound, mciSendCommand
sndPlaySound:
    xor ax, ax
    retf 6
mciSendCommand:
    mov ax, 266                  ; MCIERR_CANNOT_LOAD_DRIVER
    xor dx, dx
    retf 12

%include "lib/windows/win16/bridge.inc"
bridge timeGetTime, 3607, 0

bridge timeBeginPeriod, 3605, 2
bridge timeEndPeriod, 3606, 2
bridge timeGetDevCaps, 3604, 6
bridge timeGetSystemTime, 3601, 6
