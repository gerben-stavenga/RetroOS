bits 16
segment _TEXT public class=CODE use16
%include "lib/windows/win16/bridge.inc"

%macro gate 1
global %1
%1: int 0x83
%endmacro

bridge SetROP2, 1004, 4
bridge SetBkColor, 1001, 6
bridge SetBkMode, 1002, 4
bridge SetMapMode, 1003, 4
gate SetStretchBltMode
bridge SetTextColor, 1009, 6
gate SetWindowOrg
gate SetWindowExt
gate SetViewportOrg
gate SetViewportExt
bridge LineTo, 1019, 6
bridge MoveTo, 1020, 6
gate Arc
bridge Rectangle, 1027, 10
gate PatBlt
bridge SetPixel, 1031, 10
bridge TextOut, 1033, 12
bridge BitBlt, 1034, 20
gate StretchBlt
gate Polygon
gate Escape
bridge SelectClipRgn, 1044, 4
bridge SelectObject, 1045, 4
bridge CreateCompatibleBitmap, 1051, 6
bridge CreateCompatibleDC, 1052, 2
gate CreateDC
gate CreateEllipticRgn
gate CreateFontIndirect
gate CreatePatternBrush
bridge CreatePen, 1061, 8
bridge CreateSolidBrush, 1066, 4
gate DPtoLP
bridge DeleteDC, 1068, 2
bridge DeleteObject, 1069, 2
gate GetBitmapBits
gate GetDeviceCaps
bridge GetMapMode, 1081, 2
gate GetObject
bridge GetPixel, 1083, 6
bridge GetStockObject, 1087, 2
gate GetTextExtent
gate GetTextMetrics
gate GetViewportExt
gate GetWindowExt
gate LPtoDP
gate PlayMetaFile
gate DeleteMetaFile
gate MulDiv
bridge SetBrushOrg, 1148, 6
bridge UnrealizeObject, 1150, 2
gate CreateIC
gate GetNearestColor
gate CreateDiscardableBitmap
gate SetMetaFileBits
gate ExtTextOut
gate CreatePalette
gate AnimatePalette
gate CreateDIBitmap
gate SetDIBitsToDevice
