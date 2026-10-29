bits 16
segment _TEXT public class=CODE use16
%include "lib/windows/win16/bridge.inc"

%macro gate 1
global %1
%1: int 0x83
%endmacro

gate FatalExit
gate GetVersion
gate LocalInit
gate LocalAlloc
gate LocalReAlloc
gate LocalFree
gate LocalLock
gate LocalUnlock
gate LocalSize
gate GlobalAlloc
gate GlobalReAlloc
gate GlobalFree
gate GlobalLock
gate GlobalUnlock
gate GlobalSize
gate LockSegment
gate UnlockSegment
gate GlobalCompact
gate WaitEvent
gate GetModuleHandle
gate GetModuleUsage
gate GetModuleFileName
gate GetProcAddress
gate MakeProcInstance
gate FreeProcInstance
bridge GetProfileString, 2058, 18
gate FindResource
gate LoadResource
gate LockResource
gate FreeResource
gate OpenFile
bridge _lclose, 2081, 2
bridge _lread, 2082, 8
bridge _lcreat, 2083, 6
bridge _llseek, 2084, 8
bridge _lopen, 2085, 6
bridge _lwrite, 2086, 8
gate lstrcpy
gate lstrcat
gate lstrlen
gate InitTask
gate LoadLibrary
gate FreeLibrary
bridge GetTempFileName, 2097, 12
gate DOS3Call
gate SetErrorMode
gate OutputDebugString
gate LocalShrink
bridge GetPrivateProfileInt, 2127, 14
bridge GetPrivateProfileString, 2128, 22
gate WritePrivateProfileString
gate GetDOSEnvironment
gate GetWinFlags
bridge GetSystemDirectory, 2135, 6
gate GetDriveType
gate FatalAppExit
gate IsDBCSLeadByte

bridge WinExec, 2166, 6

bridge GetWindowsDirectory, 2134, 6

gate GlobalHandle
gate GetFreeSpace
gate AllocCStoDSAlias
gate AllocSelector
gate FreeSelector
gate PrestoChangoSelector

bridge GetProfileInt, 2057, 10
gate GetHeapSpaces

bridge hmemcpy, 2348, 12
bridge _hread, 2349, 10
bridge _hwrite, 2350, 10
