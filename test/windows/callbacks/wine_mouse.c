#include <stdarg.h>
#include <windef.h>
#include <winbase.h>
#include <wingdi.h>
#include <winuser.h>
__declspec(dllimport) BOOL WINAPI RetroWriteFile(DWORD,const void *,DWORD,DWORD *,void *);
static unsigned errors,down,painted;
static HWND child;
static void report(const char *s) {DWORD n;RetroWriteFile(1,s,lstrlenA(s),&n,0);}
static void check(BOOL ok) {if(!ok)errors++;}
static LRESULT CALLBACK proc(HWND w,UINT m,WPARAM a,LPARAM b)
{
    if(m==WM_PAINT) {
        PAINTSTRUCT p;BeginPaint(w,&p);if(w==child)painted++;EndPaint(w,&p);return 0;
    }
    if(m==WM_LBUTTONDOWN) {
        check(painted>0);
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
    WNDCLASSA c={0};HWND top,owned;MSG msg;char directory[MAX_PATH];HMODULE driver;
    MEMORYSTATUSEX memory={0};MEMORYSTATUS legacy={0};
    memory.dwLength=sizeof(memory);
    check(GlobalMemoryStatusEx(&memory));
    check(memory.ullTotalPhys>0 && memory.ullAvailPhys>0 && memory.ullAvailPhys<=memory.ullTotalPhys);
    check(memory.ullAvailVirtual>16*1024*1024 && memory.ullAvailVirtual<=memory.ullTotalVirtual);
    check(memory.ullAvailPageFile>0 && memory.ullAvailPageFile<=memory.ullTotalPageFile);
    GlobalMemoryStatus(&legacy);check(legacy.dwAvailVirtual>16*1024*1024);
    check(GetWindowsDirectoryA(directory,MAX_PATH)>0);if(lstrcmpiA(directory,"C:\\RETROOS\\WINDOWS")){report("Windows directory: ");report(directory);report("\n");check(0);}
    check(GetSystemDirectoryA(directory,MAX_PATH)>0);if(lstrcmpiA(directory,"C:\\RETROOS\\WINDOWS\\system32")){report("System directory: ");report(directory);report("\n");check(0);}
    driver=LoadLibraryA("version.dll");if(!driver)report("Dynamic DLL load failed\n");check(driver!=0);if(driver)FreeLibrary(driver);
    c.lpfnWndProc=proc;c.hInstance=GetModuleHandleA(0);c.lpszClassName="MouseProbe";
    check(RegisterClassA(&c)!=0);
    top=CreateWindowExA(0,c.lpszClassName,"mouse",WS_POPUP,30,40,180,140,0,0,c.hInstance,0);
    child=CreateWindowExA(0,c.lpszClassName,"child",WS_CHILD|WS_VISIBLE,10,20,80,60,top,0,c.hInstance,0);
    check(top && child);
    owned=CreateWindowExA(0,c.lpszClassName,"owned",WS_POPUP,0,0,10,10,child,0,c.hInstance,0);
    check(owned && GetWindow(owned,GW_OWNER)==top && GetParent(owned)==top);
    if(owned)DestroyWindow(owned);
    ShowWindow(top,SW_SHOW);SetForegroundWindow(top);SetActiveWindow(top);SetFocus(child);
    report("MOUSE READY\n");
    while(GetMessageA(&msg,0,0,0)>0) {TranslateMessage(&msg);DispatchMessageA(&msg);}
    report(errors?"MOUSE FAIL\n":"MOUSE PASS\n");report("RETROOS-SUITE-DONE\n");ExitProcess(errors?1:0);
}
