bits 32
section .text
%macro gate 1
global %1
%1: int 0x83
%endmacro
gate GdipCreateBitmapFromHBITMAP
gate GdipDisposeImage
gate GdipGetImageEncoders
gate GdipGetImageEncodersSize
gate GdipSaveImageToFile
gate GdiplusShutdown
gate GdiplusStartup
