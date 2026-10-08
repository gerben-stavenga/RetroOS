bits 32

section _TEXT use32 class=CODE

global DosQueryHType
global DosExit
global DosResetBuffer
global DosSetFilePtr
global DosClose
global DosOpen
global DosRead
global DosWrite
global DosQueryCp
global DosAllocMem
global DosFreeMem
global DosQueryModuleHandle
global DosQueryProcAddr
global DosQuerySysInfo
global DosSetRelMaxFH
global DosFlatToSel
global DosSelToFlat
global DosOpenL
global DosSetFileLocksL
global DosSetFilePtrL
global DosGetDateTime
global DosAllocSharedMem
global DosGetNamedSharedMem
global DosGetInfoBlocks

; RetroOS's replacement DOSCALLS module is an ordinary LX DLL.  Each export
; consists only of the private personality gate.  The saved EIP after INT
; identifies the export slot; the Rust personality completes the function
; return directly to the caller.
DosQueryHType:        int 0x82
DosExit:              int 0x82
DosResetBuffer:       int 0x82
DosSetFilePtr:        int 0x82
DosClose:             int 0x82
DosOpen:              int 0x82
DosRead:              int 0x82
DosWrite:             int 0x82
DosQueryCp:            int 0x82
DosAllocMem:          int 0x82
DosFreeMem:           int 0x82
DosQueryModuleHandle: int 0x82
DosQueryProcAddr:     int 0x82
DosQuerySysInfo:      int 0x82
DosSetRelMaxFH:       int 0x82
DosFlatToSel:         int 0x82
DosSelToFlat:         int 0x82
DosOpenL:              int 0x82
DosSetFileLocksL:      int 0x82
DosSetFilePtrL:         int 0x82
DosGetDateTime:         int 0x82
DosAllocSharedMem:      int 0x82
DosGetNamedSharedMem:   int 0x82
DosGetInfoBlocks:       int 0x82
global DosError
DosError: int 0x82
global DosSetFileInfo
DosSetFileInfo: int 0x82
global DosSetPathInfo
DosSetPathInfo: int 0x82
global DosSetDefaultDisk
DosSetDefaultDisk: int 0x82
global DosSetFSInfo
DosSetFSInfo: int 0x82
global DosQueryPathInfo
DosQueryPathInfo: int 0x82
global DosDeleteDir
DosDeleteDir: int 0x82
global DosSleep
DosSleep: int 0x82
global DosKillProcess
DosKillProcess: int 0x82
global DosSetCurrentDir
DosSetCurrentDir: int 0x82
global DosCopy
DosCopy: int 0x82
global DosDelete
DosDelete: int 0x82
global DosDupHandle
DosDupHandle: int 0x82
global DosFindClose
DosFindClose: int 0x82
global DosFindFirst
DosFindFirst: int 0x82
global DosFindNext
DosFindNext: int 0x82
global DosCreateDir
DosCreateDir: int 0x82
global DosMove
DosMove: int 0x82
global DosSetFileSize
DosSetFileSize: int 0x82
global DosSetFileSizeL
DosSetFileSizeL: int 0x82
global DosQueryCurrentDir
DosQueryCurrentDir: int 0x82
global DosQueryCurrentDisk
DosQueryCurrentDisk: int 0x82
global DosQueryFSAttach
DosQueryFSAttach: int 0x82
global DosQueryFSInfo
DosQueryFSInfo: int 0x82
global DosQueryFileInfo
DosQueryFileInfo: int 0x82
global DosExecPgm
DosExecPgm: int 0x82
global DosDevIOCtl
DosDevIOCtl: int 0x82
global DosBeep
DosBeep: int 0x82
global DosSetMem
DosSetMem: int 0x82
global DosLoadModule
DosLoadModule: int 0x82
global DosQueryModuleName
DosQueryModuleName: int 0x82
global DosFreeModule
DosFreeModule: int 0x82
global DosQueryAppType
DosQueryAppType: int 0x82
global DosGetResource
DosGetResource: int 0x82
global DosFreeResource
DosFreeResource: int 0x82
global DosRaiseException
global DosSetExceptionHandler
DosSetExceptionHandler: int 0x82
global DosUnsetExceptionHandler
DosUnsetExceptionHandler: int 0x82
DosRaiseException: int 0x82
global DosUnwindException
DosUnwindException: int 0x82
global DosEnumAttribute
DosEnumAttribute: int 0x82
global DosSetSignalExceptionFocus
DosSetSignalExceptionFocus: int 0x82
global DosQueryMem
DosQueryMem: int 0x82
global DosKillThread
DosKillThread: int 0x82
global DosSearchPath
DosSearchPath: int 0x82
global DosCreateThread
DosCreateThread: int 0x82
bits 16
section _TEXT16 use16 class=CODE
global DOS16MEMAVAIL
DOS16MEMAVAIL: int 0x82
