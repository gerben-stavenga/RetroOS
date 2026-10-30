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

; One worker invokes the task's multimedia callbacks serially. Reserve its
; separate 16-bit stack lazily, for the lifetime of this task.
extern GlobalAlloc
global timeSetEvent
timeSetEvent:
    push bp
    mov bp,sp
    push ds
    mov ax,seg timer_stack
    mov ds,ax
    cmp word [timer_stack],0
    jne .ready
    push word 0x40
    push dword 65536
    call far GlobalAlloc
    test ax,ax
    jz .done
    mov [timer_stack],ax
.ready:
    push word [ss:bp+18]
    push word [ss:bp+16]
    push dword [ss:bp+12]
    push dword [ss:bp+8]
    push word [ss:bp+6]
    push word [timer_stack]
    mov ds,[ss:bp-2]
    push cs
    call timer_set_bridge
.done:
    pop ds
    pop bp
    retf 14
bridge timer_set_bridge, 3602, 16
bridge timeKillEvent, 3603, 2

segment _DATA public class=DATA use16
timer_stack dw 0
group DGROUP _DATA
