bits 32
section .text
global DllMain, Ready
DllMain:
    cmp dword [esp + 8], 1
    jne .done
    mov dword [ready], 1234
.done:
    mov eax, 1
    ret 12
Ready:
    mov eax, [ready]
    ret
section .bss
ready resd 1
