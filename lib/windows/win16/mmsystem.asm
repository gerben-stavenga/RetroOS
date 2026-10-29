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
