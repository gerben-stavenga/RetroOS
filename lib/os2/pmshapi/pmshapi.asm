bits 32

section _TEXT use32 class=CODE

global PrfQueryProfileInt
PrfQueryProfileInt: int 0x82
global PrfQueryProfileString
PrfQueryProfileString: int 0x82


global PrfOpenProfile
global PrfCloseProfile
global PrfQueryProfileData
global PrfWriteProfileData

PrfOpenProfile:       int 0x82
PrfCloseProfile:      int 0x82
PrfQueryProfileData:  int 0x82
PrfWriteProfileData:  int 0x82
global WinChangeSwitchEntry
WinChangeSwitchEntry: int 0x82
global WinQuerySwitchEntry
WinQuerySwitchEntry: int 0x82
global WinQuerySwitchHandle
WinQuerySwitchHandle: int 0x82
global WinQueryTaskTitle
WinQueryTaskTitle: int 0x82
global WinSwitchToProgram
WinSwitchToProgram: int 0x82
bits 16
section _TEXT16 use16 class=CODE
global WIN16SETTITLEANDICON
WIN16SETTITLEANDICON: int 0x82
