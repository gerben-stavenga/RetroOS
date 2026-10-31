#include <stdarg.h>
#include <windef.h>
#include <winbase.h>
#include <wingdi.h>
#include <winuser.h>
static unsigned errors;
__declspec(dllimport) BOOL WINAPI RetroWriteFile(DWORD,const void *,DWORD,DWORD *,void *);
static void report(const char *text) { DWORD n; RetroWriteFile(1,text,lstrlenA(text),&n,0); }
#define CHECK(x) do {if(!(x)){errors++;report("KEY CHECK FAILED\n");}} while(0)
static LRESULT CALLBACK proc(HWND h,UINT m,WPARAM w,LPARAM l) {return DefWindowProcA(h,m,w,l);}
int main(void)
{
    static WNDCLASSA cls; HWND h; MSG msg,peek; unsigned a_down=0,a_up=0,chars=0,up=0,peeks=0;
    cls.hInstance=GetModuleHandleA(0);cls.lpfnWndProc=proc;cls.lpszClassName="WineKeyTest";
    if(!RegisterClassA(&cls)) {static char text[]="REGISTER ERROR 00000000 MODULE 00000000\n";DWORD e=GetLastError(),v=(DWORD)cls.hInstance;unsigned i;for(i=0;i<8;i++){text[15+i]="0123456789abcdef"[(e>>(28-i*4))&15];text[31+i]="0123456789abcdef"[(v>>(28-i*4))&15];}report(text);return 1;}
    h=CreateWindowExA(0,cls.lpszClassName,"Keys",WS_VISIBLE,0,0,200,100,0,0,cls.hInstance,0);
    if(!h)return 2;
    SetForegroundWindow(h);SetActiveWindow(h);SetFocus(h);
    report("KEY READY\n");
    for(;;) {
        /* A no-remove peek must not eat hardware or character messages. */
        if(PeekMessageA(&peek,0,WM_KEYFIRST,WM_KEYLAST,PM_NOREMOVE)) {
            MSG again; peeks++; CHECK(PeekMessageA(&again,0,WM_KEYFIRST,WM_KEYLAST,PM_NOREMOVE));
            CHECK(again.message==peek.message && again.wParam==peek.wParam && again.lParam==peek.lParam);
        }
        if(GetMessageA(&msg,0,0,0)<=0)break;
        if(msg.message>=WM_KEYFIRST && msg.message<=WM_KEYLAST)CHECK(msg.hwnd==h);
        if(msg.message==WM_KEYDOWN && msg.wParam=='A') {
            CHECK(GetKeyState('A')&0x8000);a_down++;
            if(a_down==1){CHECK((GetAsyncKeyState('A')&0x8001)==0x8001);CHECK(!(GetAsyncKeyState('A')&1));}
            CHECK(((msg.lParam>>16)&255)==0x1e);
            if(a_down==2)CHECK(msg.lParam&0x40000000);
            else CHECK(!(msg.lParam&0x40000000));
        }
        if(msg.message==WM_KEYUP && msg.wParam=='A') {a_up++;CHECK(!(GetKeyState('A')&0x8000));CHECK((msg.lParam&0xc0000000)==0xc0000000);}
        if(msg.message==WM_KEYDOWN && msg.wParam==VK_UP) {up++;CHECK(msg.lParam&0x01000000);}
        if(msg.message==WM_CHAR) {
            if(chars<2)CHECK(msg.wParam=='a');
            else if(chars==2)CHECK(msg.wParam=='A');
            else CHECK(msg.wParam==13);
            chars++;
            if(msg.wParam==13)PostQuitMessage(0);
        }
        TranslateMessage(&msg);
    }
    CHECK(a_down==3 && a_up==2 && chars==4 && up==1 && peeks>0);
    report(errors?"KEY FAIL\n":"KEY PASS\n");
    report("RETROOS-SUITE-DONE\n");
    return errors?1:0;
}

void start(void) {ExitProcess(main());}
