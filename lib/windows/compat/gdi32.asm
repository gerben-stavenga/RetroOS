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
gate TextOutW

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

global _TextOutW@20
_TextOutW@20: jmp TextOutW

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
