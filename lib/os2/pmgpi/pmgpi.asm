bits 32

section _TEXT use32 class=CODE

global GpiBox
global GpiDeleteBitmap
global GpiLoadBitmap
global GpiMove

GpiBox:          int 0x82
GpiDeleteBitmap: int 0x82
GpiLoadBitmap:   int 0x82
GpiMove:         int 0x82
