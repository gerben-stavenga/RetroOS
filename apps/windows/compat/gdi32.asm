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
gate CreateFontW
gate CreatePen
gate CreateSolidBrush
gate DeleteDC
gate DeleteObject
gate Ellipse
gate GetLayout
gate GetStockObject
gate GetTextExtentPoint32W
gate LineTo
gate MoveToEx
gate Polygon
gate SelectObject
gate SetBkColor
gate SetBkMode
gate SetLayout
gate SetTextColor
gate TextOutW
