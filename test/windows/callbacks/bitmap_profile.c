#include <windows.h>
#include <stdio.h>
#include <string.h>
static unsigned errors;
#define CHECK(x) do {if(!(x)){++errors;printf("bitmap/profile check failed line %u\n",__LINE__);}}while(0)
int main(void)
{
    HDC dc=CreateCompatibleDC(0);
    HBITMAP bitmap=CreateCompatibleBitmap(dc,2,2);
    BITMAPINFO info;
    /* Two DWORD-aligned 24-bit rows, bottom-up: blue/white then red/green. */
    BYTE bits[16]={255,0,0,255,255,255,0,0, 0,0,255,0,255,0,0,0};
    const char ini[]="[Options]\r\nCount=0x2a\r\nLabel=\"hello\"\r\n";
    WCHAR text[32];
    HANDLE file;
    DWORD written;
    memset(&info,0,sizeof(info));
    info.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);
    info.bmiHeader.biWidth=2;info.bmiHeader.biHeight=2;
    info.bmiHeader.biPlanes=1;info.bmiHeader.biBitCount=24;
    CHECK(SelectObject(dc,bitmap)!=0);
    CHECK(SetDIBitsToDevice(dc,0,0,2,2,0,0,0,2,bits,&info,DIB_RGB_COLORS)==2);
    CHECK(GetPixel(dc,0,0)==RGB(255,0,0));CHECK(GetPixel(dc,1,0)==RGB(0,255,0));
    CHECK(GetPixel(dc,0,1)==RGB(0,0,255));CHECK(GetPixel(dc,1,1)==RGB(255,255,255));
    info.bmiHeader.biHeight=-2;
    CHECK(SetDIBitsToDevice(dc,0,0,2,2,0,0,0,2,bits,&info,DIB_RGB_COLORS)==2);
    CHECK(GetPixel(dc,0,0)==RGB(0,0,255));CHECK(GetPixel(dc,0,1)==RGB(255,0,0));
    CHECK(SetPixel(dc,1,1,RGB(22,33,44))==RGB(22,33,44));
    CHECK(GetPixel(dc,1,1)==RGB(22,33,44));
    CHECK(DeleteDC(dc));CHECK(DeleteObject(bitmap));
    file=CreateFileA("C:\\PROFILE.INI",GENERIC_WRITE,0,0,CREATE_ALWAYS,0,0);
    CHECK(file!=INVALID_HANDLE_VALUE);
    CHECK(WriteFile(file,ini,sizeof(ini)-1,&written,0));CHECK(CloseHandle(file));
    CHECK(GetPrivateProfileIntW(L"options",L"count",7,L"C:\\PROFILE.INI")==42);
    CHECK(GetPrivateProfileIntW(L"options",L"missing",7,L"C:\\PROFILE.INI")==7);
    CHECK(GetPrivateProfileStringW(L"options",L"label",L"fallback",text,32,L"C:\\PROFILE.INI")==5);
    CHECK(text[0]=='h'&&text[4]=='o'&&text[5]==0);
    CHECK(GetPrivateProfileStringW(L"options",L"label",L"",text,3,L"C:\\PROFILE.INI")==2);
    CHECK(text[0]=='h'&&text[1]=='e'&&text[2]==0);
    CHECK(GetPrivateProfileStringW(L"options",0,L"",text,32,L"C:\\PROFILE.INI")==12);
    CHECK(text[5]==0&&text[11]==0&&text[12]==0);
    CHECK(GetPrivateProfileStringW(L"options",0,L"",text,13,L"C:\\PROFILE.INI")==12);
    CHECK(text[11]==0&&text[12]==0);
    printf("WINCALLBACK %s bitmap/profile\n",errors?"FAIL":"PASS");return errors?1:0;
}
