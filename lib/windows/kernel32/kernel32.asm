bits 32

section .text

%macro gate 1
global %1
%1: int 0x83
%endmacro

global _CloseHandle@4
_CloseHandle@4:
gate CloseHandle
gate CreateEventA
gate CreateFileA
global _ExitProcess@4
_ExitProcess@4:
gate ExitProcess
gate FlushFileBuffers
gate GetACP
gate GetCPInfo
gate GetCommandLineA
gate GetCommandLineW
gate GetConsoleMode
gate GetEnvironmentVariableA
gate GetEnvironmentVariableW
gate GetCurrentThreadId
gate GetFileType
gate GetLastError
gate GetModuleFileNameA
gate GetModuleFileNameW
global _GetModuleHandleA@4
_GetModuleHandleA@4:
gate GetModuleHandleA
gate GetModuleHandleW
gate GetOEMCP
gate GetProcAddress
gate GetStdHandle
gate GetStartupInfoA
gate GetTickCount64
gate GetVersion
gate LoadLibraryA
global _MultiByteToWideChar@24
_MultiByteToWideChar@24:
gate MultiByteToWideChar
gate ReadConsoleInputA
global _ReadFile@20
_ReadFile@20:
gate ReadFile
gate SetConsoleCtrlHandler
gate SetConsoleMode
gate SetEnvironmentVariableA
gate SetFilePointer
gate SetStdHandle
gate SetUnhandledExceptionFilter
gate UnhandledExceptionFilter
gate VirtualAlloc
gate VirtualFree
gate VirtualQuery
gate WideCharToMultiByte
gate WriteConsoleA
gate WriteFile
gate GetLocaleInfoA
gate GetLocaleInfoW
gate GetThreadLocale
gate GetUserDefaultLCID
gate GetSystemDefaultLCID
gate GetUserDefaultLangID
gate GetSystemDefaultLangID
gate ReadConsoleInputW
gate PeekConsoleInputW
gate ReadConsoleW
gate SetConsoleCP

global _CompareStringA@24
_CompareStringA@24:
gate CompareStringA

global _CompareStringW@24
_CompareStringW@24:
gate CompareStringW

global _SetLastError@4
_SetLastError@4:
gate SetLastError

global _HeapAlloc@12
_HeapAlloc@12:
gate HeapAlloc

global _HeapFree@12
_HeapFree@12:
gate HeapFree

global _GetProcessHeap@0
_GetProcessHeap@0:
gate GetProcessHeap

global _CreateFileW@28
_CreateFileW@28:
gate CreateFileW
