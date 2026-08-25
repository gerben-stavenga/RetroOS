bits 16
segment _TEXT public class=CODE use16

%macro gate 1
global %1
%1: int 0x83
%endmacro

gate FatalExit
gate LocalAlloc
gate LocalReAlloc
gate LocalFree
gate GlobalAlloc
gate GlobalReAlloc
gate GlobalFree
gate GlobalUnlock
gate LockSegment
gate UnlockSegment
gate WaitEvent
gate MakeProcInstance
gate FreeProcInstance
gate FindResource
gate LoadResource
gate LockResource
gate lstrcpy
gate InitTask
gate DOS3Call
gate OutputDebugString
gate GetPrivateProfileInt
gate GetPrivateProfileString
gate WritePrivateProfileString
gate FatalAppExit
