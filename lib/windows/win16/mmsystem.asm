; No Windows multimedia device is registered yet. Report failure to optional
; callers instead of claiming that a sound or MCI command was played.
bits 16
segment _TEXT public class=CODE use16
global sndPlaySound
sndPlaySound:
    xor ax, ax
    retf 6
%include "lib/windows/win16/bridge.inc"
bridge waveOutGetNumDevs, 3401, 0
bridge waveOutGetDevCaps, 3402, 8
bridge waveOutGetErrorText, 3403, 8
bridge waveOutOpen, 3404, 22
bridge waveOutClose, 3405, 2
bridge waveOutPrepareHeader, 3406, 8
bridge waveOutUnprepareHeader, 3407, 8
bridge waveOutWrite, 3408, 8
bridge waveOutPause, 3409, 2
bridge waveOutRestart, 3410, 2
bridge waveOutReset, 3411, 2
bridge waveOutGetPosition, 3412, 8

bridge mciSendCommand, 3701, 12
bridge mciGetDeviceID, 3703, 4
bridge mciGetErrorString, 3706, 10
bridge mciSetDriverData, 3707, 6
bridge mciGetDriverData, 3708, 2
bridge mciSetYieldProc, 3714, 10
bridge mciGetYieldProc, 3716, 6

bridge timeGetTime, 3607, 0

bridge timeBeginPeriod, 3605, 2
bridge timeEndPeriod, 3606, 2
bridge timeGetDevCaps, 3604, 6
bridge timeGetSystemTime, 3601, 6

; One worker invokes the task's multimedia callbacks serially. Reserve its
; separate 16-bit stack lazily, for the lifetime of this task.
extern GlobalAlloc, GlobalFree
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

; Buffered Win16 MMIO uses a real selector-backed allocation. The native DLL
; owns file/buffering policy; these wrappers only own that allocation's lifetime.
global mmioOpen
mmioOpen:
    push bp
    mov bp,sp
    push ebx
    push es
    sub sp,2
    mov word [ss:bp-8],0
    mov ecx,8192
    mov eax,[ss:bp+10]
    test eax,eax
    jz .flags
    les bx,[ss:bp+10]
    cmp dword [es:bx+20],0
    jne .call
    mov ecx,[es:bx+16]
    test ecx,ecx
    jnz .allocate
    mov ecx,8192
.flags:
    test dword [ss:bp+6],0x10000
    jz .call
.allocate:
    cmp ecx,65535
    ja .call
    push word 0x40
    push ecx
    call far GlobalAlloc
    mov [ss:bp-8],ax
.call:
    push dword [ss:bp+14]
    push dword [ss:bp+10]
    push dword [ss:bp+6]
    push word [ss:bp-8]
    push cs
    call mmio_open_bridge
    test ax,ax
    jnz .done
    cmp word [ss:bp-8],0
    je .done
    push ax
    push word [ss:bp-8]
    call far GlobalFree
    pop ax
.done:
    add sp,2
    pop es
    pop ebx
    pop bp
    retf 12
bridge mmio_open_bridge, 4210, 14

global mmioClose
mmioClose:
    push bp
    mov bp,sp
    push word [ss:bp+8]
    push word [ss:bp+6]
    push cs
    call mmio_close_bridge
    test ax,ax
    jnz .done
    test dx,dx
    jz .done
    push ax
    push dx
    call far GlobalFree
    pop ax
.done:
    pop bp
    retf 4
bridge mmio_close_bridge, 4211, 4
bridge mmioRead, 4212, 10
bridge mmioWrite, 4213, 10
bridge mmioSeek, 4214, 8
bridge mmioGetInfo, 4215, 8
bridge mmioSetInfo, 4216, 8
bridge mmioFlush, 4218, 4
bridge mmioAdvance, 4219, 8
bridge mmioStringToFOURCC, 4220, 6
bridge mmioDescend, 4223, 12
bridge mmioAscend, 4224, 8
bridge mmioCreateChunk, 4225, 8

segment _DATA public class=DATA use16
timer_stack dw 0
group DGROUP _DATA
