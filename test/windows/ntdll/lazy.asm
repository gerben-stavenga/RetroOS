bits 32
section .text
global DllMain, Value
extern Ready, LdrGetDllHandle
DllMain:
    cmp dword [esp + 8], 1
    jne .ok
    call Ready
    cmp eax, 1234
    jne .fail
    ; Reenter the NT loader while the outer LdrLoadDll holds its lock.
    push found
    push dependency
    push 0
    push 0
    call LdrGetDllHandle
    test eax, eax
    jnz .fail
    inc dword [attached]
.ok:
    mov eax, 1
    ret 12
.fail:
    xor eax, eax
    ret 12
Value:
    mov eax, [attached]
    ret
section .data
dependency dw 22, 24
    dd dependency_name
dependency_name dw 'I','N','I','T','D','E','P','.','D','L','L',0
section .bss
attached resd 1
found resd 1
