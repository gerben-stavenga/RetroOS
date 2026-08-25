bits 16
segment _TEXT public class=CODE use16

%macro gate 1
global %1
%1: int 0x83
%endmacro

gate SetROP2
gate SetBkColor
gate SetBkMode
gate SetMapMode
gate SetStretchBltMode
gate SetTextColor
gate SetWindowOrg
gate SetWindowExt
gate SetViewportOrg
gate SetViewportExt
gate LineTo
gate MoveTo
gate Arc
gate Rectangle
gate PatBlt
gate SetPixel
gate TextOut
gate BitBlt
gate StretchBlt
gate Polygon
gate Escape
gate SelectClipRgn
gate SelectObject
gate CreateCompatibleBitmap
gate CreateCompatibleDC
gate CreateDC
gate CreateEllipticRgn
gate CreateFontIndirect
gate CreatePatternBrush
gate CreatePen
gate CreateSolidBrush
gate DPtoLP
gate DeleteDC
gate DeleteObject
gate GetBitmapBits
gate GetDeviceCaps
gate GetMapMode
gate GetObject
gate GetPixel
gate GetStockObject
gate GetTextExtent
gate GetTextMetrics
gate GetViewportExt
gate GetWindowExt
gate LPtoDP
gate PlayMetaFile
gate DeleteMetaFile
gate MulDiv
gate SetBrushOrg
gate UnrealizeObject
gate CreateIC
gate GetNearestColor
gate CreateDiscardableBitmap
gate SetMetaFileBits
gate ExtTextOut
gate CreatePalette
gate AnimatePalette
gate CreateDIBitmap
gate SetDIBitsToDevice
