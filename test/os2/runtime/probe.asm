bits 32
section _TEXT use32 class=CODE
global DllEntry
global Probe
extern DosGetNamedSharedMem
DllEntry:
    cmp dword [esp+8], 0
    jne .ok
    push dword 3
    push dword shared_name
    push dword shared
    call DosGetNamedSharedMem
    add esp, 12
    test eax, eax
    jnz .bad
.ok:
    mov eax, 1
    ret
.bad:
    xor eax, eax
    ret
Probe:
    mov eax, [shared]
    mov eax, [eax]
    ret
section _DATA use32 class=DATA
shared: dd 0
shared_name: db '\SHAREMEM\OS2PROBE',0
