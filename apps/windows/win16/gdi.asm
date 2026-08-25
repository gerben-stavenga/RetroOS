bits 16
segment _TEXT public class=CODE use16

%macro gate 1
global %1
%1: int 0x83
%endmacro

gate SetROP2
gate LineTo
gate MoveTo
gate SetPixel
gate BitBlt
gate SelectObject
gate CreateCompatibleDC
gate CreatePen
gate CreateSolidBrush
gate DeleteDC
gate DeleteObject
gate GetDeviceCaps
gate GetStockObject
gate CreateDIBitmap
gate SetDIBitsToDevice
