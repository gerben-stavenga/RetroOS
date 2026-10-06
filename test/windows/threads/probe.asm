bits 32
section .data
attached: dd 0
section .text
global DllEntry, ProbeValue
DllEntry:
    cmp dword [esp+8], 1
    jne .done
    mov dword [attached], 1
.done:
    mov eax, 1
    ret 12
ProbeValue:
    mov eax, [attached]
    ret
