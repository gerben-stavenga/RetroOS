#include <stdarg.h>
#include <windef.h>
#include <winbase.h>
#include <wingdi.h>
#include <winuser.h>
__declspec(dllimport) BOOL WINAPI RetroWriteFile(DWORD,const void *,DWORD,DWORD *,void *);
static unsigned errors,down;
static HWND child;
static void report(const char *s) {DWORD n;RetroWriteFile(1,s,lstrlenA(s),&n,0);}
static void check(BOOL ok) {if(!ok)errors++;}
static LRESULT CALLBACK proc(HWND w,UINT m,WPARAM a,LPARAM b)
{
    if(m==WM_LBUTTONDOWN) {
        check(w==child && (short)LOWORD(b)==3 && (short)HIWORD(b)==4 && (a&MK_LBUTTON));
        check(GetKeyState(VK_LBUTTON)&0x8000);
        down++;SetCapture(w);report("MOUSE DOWN\n");return 0;
    }
    if(m==WM_LBUTTONUP) {
        POINT p;
        check(w==child && down==1 && (short)LOWORD(b)==160 && (short)HIWORD(b)==140);
        check(!(a&MK_LBUTTON));check(!(GetKeyState(VK_LBUTTON)&0x8000));
        check(GetCursorPos(&p) && p.x==200 && p.y==200);
        ReleaseCapture();PostQuitMessage(0);return 0;
    }
    return DefWindowProcA(w,m,a,b);
}
void start(void)
{
    WNDCLASSA c={0};HWND top;MSG msg;
    c.lpfnWndProc=proc;c.hInstance=GetModuleHandleA(0);c.lpszClassName="MouseProbe";
    check(RegisterClassA(&c)!=0);
    top=CreateWindowExA(0,c.lpszClassName,"mouse",WS_POPUP|WS_VISIBLE,30,40,180,140,0,0,c.hInstance,0);
    child=CreateWindowExA(0,c.lpszClassName,"child",WS_CHILD|WS_VISIBLE,10,20,80,60,top,0,c.hInstance,0);
    check(top && child);SetForegroundWindow(top);SetActiveWindow(top);SetFocus(child);
    report("MOUSE READY\n");
    while(GetMessageA(&msg,0,0,0)>0) {TranslateMessage(&msg);DispatchMessageA(&msg);}
    report(errors?"MOUSE FAIL\n":"MOUSE PASS\n");report("RETROOS-SUITE-DONE\n");ExitProcess(errors?1:0);
}
