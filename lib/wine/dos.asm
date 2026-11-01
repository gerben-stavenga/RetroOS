bits 32
section .text

; Wine's register-entry APIs pass an i386 CONTEXT. Execute DOS with the
; application's segmented registers, on this DLL's ordinary 32-bit stack.
; A blocking DOS call resumes here through the existing PM DOS continuation.
global _RetroDosInterrupt@4
_RetroDosInterrupt@4:
    pushfd
    pushad
    push ds
    push es
    mov ebp,[esp+48]             ; CONTEXT argument, after 44 bytes of saves
    push ebp                    ; keep the context independent of DOS's BP
    push dword [ebp+0x98]        ; SegDs
    push dword [ebp+0x94]        ; SegEs
    mov edi,[ebp+0x9c]
    mov esi,[ebp+0xa0]
    mov ebx,[ebp+0xa4]
    mov edx,[ebp+0xa8]
    mov ecx,[ebp+0xac]
    mov eax,[ebp+0xb0]
    mov ebp,[ebp+0xb4]
    pop es
    pop ds
    int 0x21
    pushfd
    pushad
    mov ebp,[ss:esp+36]          ; CONTEXT, below result registers and flags
    mov ax,ds
    mov dx,es
    mov cx,[ss:esp+44]           ; original DLL data selector
    mov ds,cx
    movzx eax,ax
    mov [ebp+0x98],eax
    movzx edx,dx
    mov [ebp+0x94],edx
%macro result 2
    mov eax,[ss:esp+%1]
    mov [ebp+%2],eax
%endmacro
    result 0,  0x9c             ; EDI
    result 4,  0xa0             ; ESI
    result 8,  0xb4             ; EBP
    result 16, 0xa4             ; EBX
    result 20, 0xa8             ; EDX
    result 24, 0xac             ; ECX
    result 28, 0xb0             ; EAX
    mov eax,[ss:esp+32]
    and eax,0x8d5               ; DOS condition flags; retain caller control flags
    and dword [ebp+0xc0],~0x8d5
    or [ebp+0xc0],eax
    add esp,40                  ; results, flags and context anchor
    pop es
    pop ds
    popad
    popfd
    ret 4
