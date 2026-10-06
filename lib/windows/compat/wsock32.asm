bits 32
section .text
%macro gate 1
global %1
%1: int 0x83
%endmacro
gate WSACleanup
gate WSAGetLastError
gate WSASetLastError
gate WSAStartup
gate accept
gate bind
gate closesocket
gate connect
gate gethostbyname
gate getsockname
gate htons
gate inet_addr
gate inet_ntoa
gate listen
gate ntohs
gate recv
gate select
gate send
gate setsockopt
gate shutdown
gate socket
