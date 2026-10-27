#include <windows.h>
#include <stdio.h>
#include <string.h>
static unsigned errors;
#define CHECK(x) do {if(!(x)){++errors;printf("bitmap/profile check failed line %u\n",__LINE__);}}while(0)
static void CALLBACK close_message(HWND window, UINT msg, UINT_PTR id, DWORD ticks)
{
    HWND button=GetFocus();
    HWND dialog=GetParent(button);
    KillTimer(0,id);
    CHECK(GetDlgCtrlID(button)==IDCANCEL);
    CHECK(GetDlgItem(dialog,IDOK)!=0);
    CHECK(GetDlgItem(dialog,IDCANCEL)!=0);
    SendMessageW(dialog,WM_COMMAND,IDCANCEL,0);
}
static LRESULT CALLBACK paint_order_proc(HWND w, UINT m, WPARAM wp, LPARAM lp)
{
    if(m==WM_PAINT) {
        PAINTSTRUCT ps;
        RECT r;
        HDC dc=BeginPaint(w,&ps);
        GetClientRect(w,&r);
        FillRect(dc,&r,GetStockObject(GetParent(w)?BLACK_BRUSH:WHITE_BRUSH));
        EndPaint(w,&ps);
        return 0;
    }
    return DefWindowProcA(w,m,wp,lp);
}
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
    /* SRCCOPY respects source bounds and destination clips, ignores ROP2,
       and snapshots overlapping copies within the same bitmap. */
    {
        HDC dst=CreateCompatibleDC(0);
        HBITMAP db=CreateCompatibleBitmap(dst,4,4);
        HRGN clip=CreateRectRgn(1,1,3,3);
        int x,y;
        SelectObject(dst,db);
        for(y=0;y<4;++y) for(x=0;x<4;++x) SetPixel(dst,x,y,RGB(9,8,7));
        SelectClipRgn(dst,clip);
        SetROP2(dst,R2_BLACK);
        CHECK(BitBlt(dst,0,0,4,4,dc,-1,-1,SRCCOPY));
        CHECK(GetPixel(dst,1,1)==RGB(0,0,255));
        CHECK(GetPixel(dst,2,1)==RGB(255,255,255));
        CHECK(GetPixel(dst,2,2)==RGB(22,33,44));
        SelectClipRgn(dst,0);
        CHECK(GetPixel(dst,0,0)==RGB(9,8,7));
        CHECK(GetPixel(dst,3,3)==RGB(9,8,7));
        CHECK(BitBlt(dst,2,2,2,2,dst,1,1,SRCCOPY));
        CHECK(GetPixel(dst,2,2)==RGB(0,0,255));
        CHECK(GetPixel(dst,3,3)==RGB(22,33,44));
        /* Classic icon masks: preserve, invert, black and white. */
        SelectClipRgn(dst,0);SetROP2(dst,R2_COPYPEN);
        SetPixel(dst,0,0,RGB(10,20,30));SetPixel(dst,1,0,RGB(10,20,30));
        SetPixel(dst,0,1,RGB(10,20,30));SetPixel(dst,1,1,RGB(10,20,30));
        SetPixel(dc,0,0,RGB(255,255,255));SetPixel(dc,1,0,RGB(255,255,255));
        SetPixel(dc,0,1,0);SetPixel(dc,1,1,0);
        SetROP2(dst,R2_BLACK); /* BitBlt must ignore this. */
        CHECK(BitBlt(dst,0,0,2,2,dc,0,0,SRCAND));
        SetPixel(dc,0,0,0);SetPixel(dc,1,0,RGB(255,255,255));
        SetPixel(dc,0,1,0);SetPixel(dc,1,1,RGB(255,255,255));
        CHECK(BitBlt(dst,0,0,2,2,dc,0,0,SRCINVERT));
        CHECK(GetPixel(dst,0,0)==RGB(10,20,30));
        CHECK(GetPixel(dst,1,0)==RGB(245,235,225));
        CHECK(GetPixel(dst,0,1)==0);CHECK(GetPixel(dst,1,1)==RGB(255,255,255));
        DeleteObject(clip);DeleteDC(dst);DeleteObject(db);
    }
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
    /* Pending parent paint must precede child paint, even if the child
       was invalidated first, or the parent wipes out its finished pixels. */
    {
        WNDCLASSA wc={0};
        MSG msg;
        HWND parent,child;
        HDC pdc;
        wc.lpfnWndProc=paint_order_proc;wc.lpszClassName="PaintOrder";
        wc.hInstance=GetModuleHandleA(0);
        CHECK(RegisterClassA(&wc)!=0);
        parent=CreateWindowA("PaintOrder","",WS_POPUP|WS_VISIBLE,0,0,100,80,0,0,wc.hInstance,0);
        child=CreateWindowA("PaintOrder","",WS_CHILD|WS_VISIBLE,10,10,30,30,parent,0,wc.hInstance,0);
        UpdateWindow(parent);
        InvalidateRect(child,0,TRUE);
        InvalidateRect(parent,0,TRUE);
        CHECK(PeekMessageA(&msg,0,WM_PAINT,WM_PAINT,PM_REMOVE));
        CHECK(msg.hwnd==parent);DispatchMessageA(&msg);
        CHECK(PeekMessageA(&msg,0,WM_PAINT,WM_PAINT,PM_REMOVE));
        CHECK(msg.hwnd==child);DispatchMessageA(&msg);
        pdc=GetDC(parent);CHECK(GetPixel(pdc,15,15)==RGB(0,0,0));ReleaseDC(parent,pdc);
        DestroyWindow(parent);
        UnregisterClassA("PaintOrder",wc.hInstance);
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
    CHECK(SetTimer(0,0,20,close_message)!=0);
    CHECK(MessageBoxW(0,L"Choose Cancel.",L"Shared modal message",MB_OKCANCEL|MB_DEFBUTTON2)==IDCANCEL);
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
