bits 32
section .text
global DllMain, Rejected
DllMain:
    xor eax, eax
    ret 12
Rejected:
    ud2
