bits 16
section _TEXT use16 class=CODE
global KbdCharIn
KbdCharIn: int 0x82
global KbdGetStatus
KbdGetStatus: int 0x82
global KbdSetStatus
KbdSetStatus: int 0x82
global KbdPeek
KbdPeek: int 0x82
