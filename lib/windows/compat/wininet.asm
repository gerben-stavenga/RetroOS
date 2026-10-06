bits 32
section .text
%macro gate 1
global %1
%1: int 0x83
%endmacro
gate InternetCloseHandle
gate InternetOpenA
gate InternetOpenUrlA
gate InternetReadFile
