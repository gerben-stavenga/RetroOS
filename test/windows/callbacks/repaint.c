#include <windows.h>
static LRESULT CALLBACK proc(HWND h,UINT m,WPARAM w,LPARAM l)
{
    return DefWindowProcA(h,m,w,l);
}
int main(void)
{
    WNDCLASSA cls={0};HWND h;HDC dc;HBRUSH brush;RECT rect={0,0,160,80};
    cls.hInstance=GetModuleHandleA(0);cls.lpfnWndProc=proc;cls.lpszClassName="RepaintTest";
    if(!RegisterClassA(&cls))return 1;
    h=CreateWindowExA(0,cls.lpszClassName,"Repaint",WS_VISIBLE,0,0,160,80,0,0,cls.hInstance,0);
    if(!h)return 2;
    UpdateWindow(h);
    /* Let initial paint/cursor damage drain before drawing through GetDC. */
    Sleep(50);
    dc=GetDC(h);brush=CreateSolidBrush(RGB(255,0,0));
    FillRect(dc,&rect,brush);DeleteObject(brush);ReleaseDC(h,dc);
    Sleep(50);
    dc=GetDC(h);brush=CreateSolidBrush(RGB(0,0,255));
    FillRect(dc,&rect,brush);DeleteObject(brush);
    SetTextColor(dc,RGB(255,255,255));TextOutW(dc,10,10,L"Ready",5);
    SetPixel(dc,100,40,RGB(0,255,0));ReleaseDC(h,dc);
    OutputDebugStringA("WINREPAINT READY");
    Sleep(10000);
    return 0;
}
