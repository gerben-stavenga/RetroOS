bits 32

section .text

%macro gate 1
global %1
%1: int 0x83
%endmacro

gate CloseHandle
gate CreateEventA
gate CreateFileA
gate ExitProcess
gate FlushFileBuffers
gate GetACP
gate GetCPInfo
gate GetCommandLineA
gate GetCommandLineW
gate GetConsoleMode
gate GetCurrentThreadId
gate GetFileType
gate GetLastError
gate GetModuleFileNameA
gate GetModuleFileNameW
gate GetModuleHandleA
gate GetOEMCP
gate GetProcAddress
gate GetStdHandle
gate GetVersion
gate LoadLibraryA
gate MultiByteToWideChar
gate ReadConsoleInputA
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
