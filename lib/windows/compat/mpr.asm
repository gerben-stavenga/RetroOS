bits 32
section .text
%macro gate 1
global %1
%1: int 0x83
%endmacro
gate WNetAddConnection2A
gate WNetCancelConnection2A
gate WNetCloseEnum
gate WNetEnumResourceA
gate WNetGetConnectionA
gate WNetOpenEnumA
gate WNetGetUniversalNameA
