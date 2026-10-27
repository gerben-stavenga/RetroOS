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
    /* Rectangle honors selected brush/pen and excludes right/bottom edges. */
    {
        HDC rd=CreateCompatibleDC(0);
        HBITMAP rb=CreateCompatibleBitmap(rd,16,16);
        HBRUSH red=CreateSolidBrush(RGB(255,0,0));
        HPEN black=CreatePen(PS_SOLID,1,RGB(0,0,0));
        HGDIOBJ oldb,oldp;
        SelectObject(rd,rb);
        oldb=SelectObject(rd,red);oldp=SelectObject(rd,black);
        CHECK(Rectangle(rd,2,2,10,10));
        CHECK(GetPixel(rd,3,3)==RGB(255,0,0));
        CHECK(GetPixel(rd,2,2)==RGB(0,0,0));
        CHECK(GetPixel(rd,10,10)!=RGB(255,0,0));
        SetPixel(rd,4,4,RGB(0,0,255));
        SelectObject(rd,GetStockObject(NULL_BRUSH));
        CHECK(Rectangle(rd,2,2,10,10));
        CHECK(GetPixel(rd,4,4)==RGB(0,0,255));
        SelectObject(rd,red);SelectObject(rd,GetStockObject(NULL_PEN));
        CHECK(Rectangle(rd,2,2,10,10));
        CHECK(GetPixel(rd,2,2)==RGB(255,0,0));
        SelectObject(rd,oldb);SelectObject(rd,oldp);
        DeleteDC(rd);DeleteObject(rb);DeleteObject(red);DeleteObject(black);
    }
    /* Group frames must not erase sibling controls; auto-radio buttons share
       state and painting regardless of whether the caller is PE or NE. */
    {
        HWND parent=CreateWindowA("STATIC","",WS_POPUP|WS_VISIBLE,0,0,250,80,0,0,0,0);
        HWND first=CreateWindowA("BUTTON","first",WS_CHILD|WS_VISIBLE|WS_GROUP|BS_AUTORADIOBUTTON,10,20,100,20,parent,(HMENU)1,0,0);
        HWND second=CreateWindowA("BUTTON","second",WS_CHILD|WS_VISIBLE|BS_AUTORADIOBUTTON,120,20,100,20,parent,(HMENU)2,0,0);
        HWND group=CreateWindowA("BUTTON","Choices",WS_CHILD|WS_VISIBLE|BS_GROUPBOX,0,0,240,60,parent,(HMENU)3,0,0);
        HDC cd;
        CHECK(parent&&first&&second&&group);
        SendMessageA(first,BM_CLICK,0,0);
        CHECK(SendMessageA(first,BM_GETCHECK,0,0)==BST_CHECKED);
        SendMessageA(second,BM_CLICK,0,0);
        CHECK(SendMessageA(first,BM_GETCHECK,0,0)==BST_UNCHECKED);
        CHECK(SendMessageA(second,BM_GETCHECK,0,0)==BST_CHECKED);
        UpdateWindow(parent);UpdateWindow(first);UpdateWindow(second);
        cd=GetDC(first);
        CHECK(GetPixel(cd,0,9)==RGB(0,0,0));
        UpdateWindow(group);
        CHECK(GetPixel(cd,0,9)==RGB(0,0,0));
        ReleaseDC(first,cd);DestroyWindow(parent);
    }
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
