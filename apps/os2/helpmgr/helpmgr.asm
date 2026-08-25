bits 32

section _TEXT use32 class=CODE

global WinCreateHelpInstance
global WinDestroyHelpInstance
global WinAssociateHelpInstance

WinCreateHelpInstance:    int 0x82
WinDestroyHelpInstance:   int 0x82
WinAssociateHelpInstance: int 0x82
