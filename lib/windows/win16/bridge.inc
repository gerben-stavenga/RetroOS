%macro bridge 3
global %1
%1:
    push word %2
    call bridge_enter
    add sp, 2
    retf %3
%endmacro

; Ordinary guest exports enter the shared 32-bit USER implementation. The
; loader binds these two far pointers before making this segment executable.
global RetroBridgeConfig
RetroBridgeConfig:
    dd 0
    dw 0
    dd 0
    dw 0

bridge_enter:
    pushfd
    pushad
    push ds
    push es
    push fs
    push gs
    movzx esi, sp
    xor eax, eax
    mov ax, ss
    xor edx, edx
    mov dx, cs
    mov edi, bridge_return
    jmp dword far [cs:RetroBridgeConfig]
bridge_return:
    pop gs
    pop fs
    pop es
    pop ds
    popad
    popfd
    ret

global RetroBridgeCallbackReturn
RetroBridgeCallbackReturn:
    jmp dword far [cs:RetroBridgeConfig+6]
