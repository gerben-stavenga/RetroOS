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
