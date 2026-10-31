bits 32
global _start
extern CreateCompatibleDC, DeleteDC, CreateFontIndirectW, SelectObject, DeleteObject
extern GetTextExtentPoint32W, GetTextFaceW, GetGlyphOutlineW
extern RetroWriteFile, NtTerminateProcess
section .text
_start:
    push 0
    call CreateCompatibleDC
    test eax,eax
    jz failed
    mov [dc],eax
    push font
    call CreateFontIndirectW
    test eax,eax
    jz failed
    mov [handle],eax
    push eax
    push dword [dc]
    call SelectObject
    mov [previous],eax
    push face
    push 32
    push dword [dc]
    call GetTextFaceW
    test eax,eax
    jz failed
    cmp dword [face],0x00610054 ; Ta
    jne failed
    cmp dword [face+4],0x006f0068 ; ho
    jne failed
    push extent
    push 4
    push sample
    push dword [dc]
    call GetTextExtentPoint32W
    test eax,eax
    jz failed
    cmp dword [extent],0
    jle failed
    cmp dword [extent+4],0
    jle failed
    push matrix
    push bitmap
    push 4096
    push metrics
    push 6 ; GGO_GRAY8_BITMAP
    push 'A'
    push dword [dc]
    call GetGlyphOutlineW
    test eax,eax
    jz failed
    cmp eax,4096
    ja failed
    mov ecx,eax
    mov esi,bitmap
    xor eax,eax
.sum:
    or al,[esi]
    inc esi
    loop .sum
    test al,al
    jz failed
    push dword [previous]
    push dword [dc]
    call SelectObject
    push dword [handle]
    call DeleteObject
    push dword [dc]
    call DeleteDC
    mov esi,success
    xor ebx,ebx
    jmp done
failed:
    mov esi,failure
    mov ebx,1
done:
    push 0
    push written
    push 11
    push esi
    push 1
    call RetroWriteFile
    push ebx
    push -1
    call NtTerminateProcess
    ud2
section .data
success db 'FONTS PASS',10
failure db 'FONTS FAIL',10
font:
    dd -16,0,0,0,400
    db 0,0,0,1,0,0,0,0
    dw 'T','a','h','o','m','a',0
    times 25 dw 0
sample dw 'C','i','v','!'
matrix dd 65536,0,0,65536
section .bss
dc resd 1
handle resd 1
previous resd 1
written resd 1
extent resd 2
metrics resb 20
face resw 32
bitmap resb 4096
