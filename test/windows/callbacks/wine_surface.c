/* Child DCs must address the owning top-level Wine surface. */
#include <stdarg.h>
#include <windef.h>
#include <winbase.h>
#include <wingdi.h>
#include <winuser.h>
__declspec(dllimport) BOOL WINAPI RetroWriteFile(DWORD,const void *,DWORD,DWORD *,void *);
static unsigned errors;
static void check(BOOL ok) { if(!ok) errors++; }
static LRESULT CALLBACK proc(HWND w,UINT m,WPARAM a,LPARAM b) {return DefWindowProcA(w,m,a,b);}
void start(void)
{
    WNDCLASSA c={0}; HWND top,child,nested; HDC dc,parent; RECT clip; DWORD written;
    c.lpfnWndProc=proc;c.hInstance=GetModuleHandleA(0);c.lpszClassName="SurfaceProbe";
    ATOM atom=RegisterClassA(&c);
    check(atom!=0);
    top=CreateWindowExA(0,c.lpszClassName,"surface",WS_POPUP|WS_VISIBLE,30,40,180,140,0,0,c.hInstance,0);
    child=CreateWindowExA(0,c.lpszClassName,"child",WS_CHILD|WS_VISIBLE,10,20,80,60,top,0,c.hInstance,0);
    nested=CreateWindowExA(0,c.lpszClassName,"nested",WS_CHILD|WS_VISIBLE,5,6,30,20,child,0,c.hInstance,0);
    check(top && child && nested);
    dc=GetDC(nested);check(dc!=0);
    check(GetClipBox(dc,&clip)!=ERROR);
    check(clip.left==0 && clip.top==0 && clip.right==30 && clip.bottom==20);
    check(SetPixel(dc,3,4,RGB(17,34,51))==RGB(17,34,51));
    ReleaseDC(nested,dc);
    parent=GetDC(top);check(parent!=0);
    check(GetPixel(parent,18,30)==RGB(17,34,51));
    ReleaseDC(top,parent);
    /* Cross several shared-session allocation blocks. Every query must reuse
     * its mapping, including the first record in each 64 KiB block. */
    HWND many[32];
    for(unsigned i=0;i<32;i++) {
        many[i]=CreateWindowExA(0,c.lpszClassName,"",WS_CHILD,0,0,1,1,top,0,c.hInstance,0);
        check(many[i]!=0);
    }
    for(unsigned i=0;i<1000;i++)
        for(unsigned j=0;j<32;j++) check(GetClassLongA(many[j],GCW_ATOM)==atom);
    DestroyWindow(top);
    if(errors) RetroWriteFile(1,"SURFACE FAIL\n",13,&written,0);
    else RetroWriteFile(1,"SURFACE PASS\n",13,&written,0);
    ExitProcess(errors?1:0);
}
