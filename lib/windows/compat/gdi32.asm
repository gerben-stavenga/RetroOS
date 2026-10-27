bits 32
section .text
%macro gate 1
global %1
%1: int 0x83
%endmacro
gate Arc
gate BitBlt
gate CreateCompatibleBitmap
gate CreateCompatibleDC
gate CreatePen
gate CreateSolidBrush
gate Ellipse
gate GetLayout
gate GetStockObject
gate GetTextExtentPoint32W
gate LineTo
gate MoveToEx
gate Polygon
gate SetBkColor
gate SetBkMode
gate SetLayout
gate SetTextColor
gate GetBkColor
gate GetTextColor
global _RetroGdiTextOutW@20
_RetroGdiTextOutW@20:
gate RetroGdiTextOutW

global _RetroGdiBitmap@12
_RetroGdiBitmap@12:
gate RetroGdiBitmap

gate GetPixel

global _RetroGdiDeleteObject@4
_RetroGdiDeleteObject@4:
gate RetroGdiDeleteObject

global _RetroGdiClip@12
_RetroGdiClip@12:
gate RetroGdiClip

global _RetroGdiBounds@8
_RetroGdiBounds@8:
gate RetroGdiBounds

global _RetroGdiRop@8
_RetroGdiRop@8:
gate RetroGdiRop

global _RetroGdiDeleteDC@4
_RetroGdiDeleteDC@4:
gate RetroGdiDeleteDC

global _GetCurrentPositionEx@8
_GetCurrentPositionEx@8:
gate GetCurrentPositionEx
global _MoveToEx@16
_MoveToEx@16: jmp MoveToEx
global _GetTextExtentPoint32W@16
_GetTextExtentPoint32W@16: jmp GetTextExtentPoint32W
global _GetPixel@12
_GetPixel@12: jmp GetPixel

global _RetroGdiSelectObject@8
_RetroGdiSelectObject@8:
gate RetroGdiSelectObject

global _RetroGdiObject@12
_RetroGdiObject@12:
gate RetroGdiObject

global _CreateCompatibleDC@4
_CreateCompatibleDC@4: jmp CreateCompatibleDC

global _BitBlt@36
_BitBlt@36: jmp BitBlt

global _RetroGdiFillRect@12
_RetroGdiFillRect@12:
gate RetroGdiFillRect
global _RetroGdiCurrentObject@8
_RetroGdiCurrentObject@8:
gate RetroGdiCurrentObject
global _Polygon@12
_Polygon@12: jmp Polygon

global _GetObjectType@4
_GetObjectType@4:
gate GetObjectType

global _GetBkColor@4
_GetBkColor@4: jmp GetBkColor
global _CreateSolidBrush@4
_CreateSolidBrush@4: jmp CreateSolidBrush
