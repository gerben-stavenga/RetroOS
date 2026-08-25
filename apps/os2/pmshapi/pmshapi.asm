bits 32

section _TEXT use32 class=CODE

global PrfOpenProfile
global PrfCloseProfile
global PrfQueryProfileData
global PrfWriteProfileData

PrfOpenProfile:       int 0x82
PrfCloseProfile:      int 0x82
PrfQueryProfileData:  int 0x82
PrfWriteProfileData:  int 0x82
