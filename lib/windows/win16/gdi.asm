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
bridge PatBlt, 1029, 14
bridge SetPixel, 1031, 10
bridge TextOut, 1033, 12
bridge BitBlt, 1034, 20
gate StretchBlt
bridge Polygon, 1036, 8
gate Escape
bridge SelectClipRgn, 1044, 4
bridge SelectObject, 1045, 4
bridge CreateCompatibleBitmap, 1051, 6
bridge CreateCompatibleDC, 1052, 2
gate CreateDC
gate CreateEllipticRgn
bridge CreateFontIndirect, 1057, 4
bridge CreatePatternBrush, 1060, 2
bridge CreatePen, 1061, 8
bridge CreateSolidBrush, 1066, 4
gate DPtoLP
bridge DeleteDC, 1068, 2
bridge DeleteObject, 1069, 2
bridge GetBitmapBits, 1074, 10
bridge GetDeviceCaps, 1080, 4
bridge GetMapMode, 1081, 2
bridge GetObject, 1082, 8
bridge GetPixel, 1083, 6
bridge GetStockObject, 1087, 2
bridge GetTextExtent, 1091, 8
gate GetTextMetrics
gate GetViewportExt
gate GetWindowExt
gate LPtoDP
gate PlayMetaFile
gate DeleteMetaFile
bridge MulDiv, 1128, 6
bridge SetBrushOrg, 1148, 6
bridge UnrealizeObject, 1150, 2
gate CreateIC
gate GetNearestColor
gate CreateDiscardableBitmap
gate SetMetaFileBits
bridge ExtTextOut, 1351, 22
bridge CreatePalette, 1360, 4
bridge AnimatePalette, 1367, 10
gate CreateDIBitmap
gate SetDIBitsToDevice

bridge GetBkColor, 1075, 2
bridge GetTextColor, 1090, 2
bridge SetTextAlign, 1346, 4
bridge ExtFloodFill, 1372, 12

bridge SetPolyFillMode, 1006, 4
bridge Polyline, 1037, 8
bridge CreateBitmap, 1048, 12
bridge CreateFont, 1056, 30
bridge GetBkMode, 1076, 2
bridge SetBitmapBits, 1106, 10
bridge AddFontResource, 1119, 4
bridge RemoveFontResource, 1136, 4
bridge GetBitmapDimension, 1162, 2
bridge SetBitmapDimension, 1163, 6
bridge EnumFontFamilies, 1330, 14
bridge SetPaletteEntries, 1364, 10
bridge GetSystemPaletteEntries, 1375, 10

bridge GetNearestPaletteIndex, 1370, 6

bridge MoveToEx, 1483, 10

bridge GetTextExtentPoint, 1471, 12

bridge GetTextAlign, 1345, 2
bridge GetPaletteEntries, 1363, 10
bridge GetBitmapDimensionEx, 1468, 6

bridge ExcludeClipRect, 1021, 10
bridge IntersectClipRect, 1022, 10
