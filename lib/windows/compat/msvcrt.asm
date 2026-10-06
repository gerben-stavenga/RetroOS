bits 32
section .text
%macro gate 1
global %1
%1: int 0x83
%endmacro
gate __dllonexit
gate _amsg_exit
gate _initterm
gate _lock
gate _onexit
gate _unlock
gate abort
gate calloc
gate free
gate fwrite
gate malloc
gate strcpy
gate strlen
gate strncmp
gate vfprintf
section .data
global _iob
_iob: times 96 db 0
