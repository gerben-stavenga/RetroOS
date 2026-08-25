bits 32
section .text
%macro gate 1
global %1
%1: int 0x83
%endmacro
gate RegCloseKey
gate RegCreateKeyExW
gate RegQueryValueExW
gate RegSetValueExW
