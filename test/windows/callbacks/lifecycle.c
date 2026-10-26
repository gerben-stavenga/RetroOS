#include <windows.h>
#include <stdio.h>
#include <string.h>
static unsigned errors, created, destroyed, ncdestroyed, enumerated, moved;
static WNDPROC original;
#define CHECK(x) do { if (!(x)) { printf("line %u failed\n", __LINE__); ++errors; } } while(0)
static LRESULT CALLBACK proc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    if(m==WM_CREATE) ++created;
    if(m==WM_DESTROY) ++destroyed;
    if(m==WM_NCDESTROY) ++ncdestroyed;
    if(m==WM_WINDOWPOSCHANGING && moved) ((WINDOWPOS *)l)->x+=3;
    return DefWindowProcA(h,m,w,l);
}
static LRESULT CALLBACK subclass(HWND h, UINT m, WPARAM w, LPARAM l)
{
    if(m==WM_APP) return 123;
    return CallWindowProcA(original,h,m,w,l);
}
static BOOL CALLBACK enumerate(HWND h, LPARAM p)
{
    CHECK(IsWindow(h)); ++enumerated;
    return p!=0;
}
int main(void)
{
    WNDCLASSA c={0},info;
    HWND parent,child,child2;
    RECT r;
    POINT p;
    char title[32];
    ATOM atom;
    DWORD pid;
    c.lpfnWndProc=proc;c.lpszClassName="Lifetime";c.hInstance=GetModuleHandleA(0);
    c.cbClsExtra=8;c.cbWndExtra=12;
    atom=RegisterClassA(&c);
    CHECK(atom!=0);
    CHECK(RegisterClassA(&c)==0 && GetLastError()==1410);
    CHECK(GetClassInfoA(c.hInstance,c.lpszClassName,&info));
    CHECK(info.lpfnWndProc==proc && info.cbWndExtra==12 && info.cbClsExtra==8);
    parent=CreateWindowExA(0,c.lpszClassName,"Parent",WS_POPUP|WS_VISIBLE,10,20,100,80,0,0,c.hInstance,0);
    child=CreateWindowExA(0,c.lpszClassName,"Child",WS_CHILD|WS_VISIBLE,4,5,30,20,parent,(HMENU)21,c.hInstance,0);
    child2=CreateWindowExA(0,c.lpszClassName,"Other",WS_CHILD,8,9,30,20,parent,(HMENU)22,c.hInstance,0);
    CHECK(parent && child && child2 && created==3);
    CHECK(IsChild(parent,child) && !IsChild(child,parent));
    CHECK(GetParent(child)==parent && GetDlgItem(parent,21)==child && GetDlgCtrlID(child2)==22);
    CHECK(GetWindowThreadProcessId(parent,&pid)==GetCurrentThreadId() && pid==GetCurrentProcessId());
    CHECK(!UnregisterClassA(c.lpszClassName,c.hInstance) && GetLastError()==1412);
    CHECK(GetClassLongA(child,GCW_ATOM)==atom);
    CHECK(SetClassLongA(parent,4,77)==0 && GetClassLongA(child,4)==77);
    CHECK(SetWindowLongA(child,8,88)==0 && GetWindowLongA(child,8)==88);
    CHECK(SetWindowLongA(child,GWL_USERDATA,42)==0 && GetWindowLongA(child,GWL_USERDATA)==42);
    CHECK(GetClassNameA(parent,title,sizeof(title))==8 && !strcmp(title,"Lifetime"));
    CHECK(GetWindowTextA(parent,title,sizeof(title))==6 && !strcmp(title,"Parent"));
    CHECK(SetWindowTextA(parent,"Changed"));
    CHECK(GetWindowTextLengthA(parent)==7);
    CHECK(GetWindowTextA(parent,title,4)==3 && !strcmp(title,"Cha"));
    CHECK(IsWindowVisible(child) && !IsWindowVisible(child2));
    CHECK(ShowWindow(parent,SW_HIDE));CHECK(!IsWindowVisible(child));
    CHECK(!ShowWindow(parent,SW_SHOW));CHECK(IsWindowVisible(child));
    CHECK(!EnableWindow(child,FALSE) && !IsWindowEnabled(child));
    CHECK(EnableWindow(child,TRUE) && IsWindowEnabled(child));
    CHECK(GetWindowRect(child,&r));CHECK(r.left==14 && r.top==25 && r.right==44 && r.bottom==45);
    p.x=0;p.y=0;CHECK(ClientToScreen(child,&p) && p.x==14 && p.y==25);
    CHECK(ScreenToClient(parent,&p) && p.x==4 && p.y==5);
    moved=1;CHECK(SetWindowPos(parent,0,30,40,120,90,SWP_NOZORDER));moved=0;
    CHECK(GetWindowRect(parent,&r));CHECK(r.left==33 && r.top==40 && r.right==153 && r.bottom==130);
    original=(WNDPROC)SetWindowLongA(child,GWL_WNDPROC,(LONG)subclass);
    CHECK(original==proc && SendMessageA(child,WM_APP,0,0)==123);
    CHECK(SetWindowLongA(child,GWL_WNDPROC,(LONG)original)==(LONG)subclass);
    enumerated=0;CHECK(EnumChildWindows(parent,enumerate,1));CHECK(enumerated==2);
    enumerated=0;CHECK(!EnumWindows(enumerate,0));CHECK(enumerated==1);
    CHECK(!SetParent(parent,child) && GetLastError()==87);
    CHECK(DestroyWindow(parent));CHECK(!IsWindow(parent) && !IsWindow(child) && !IsWindow(child2));
    CHECK(destroyed==3 && ncdestroyed==3);
    CHECK(UnregisterClassA(c.lpszClassName,c.hInstance));
    CHECK(!GetClassInfoA(c.hInstance,c.lpszClassName,&info) && GetLastError()==1411);
    if(errors) {printf("WINCALLBACK FAIL %u\n",errors);return 1;}
    puts("WINCALLBACK PASS");return 0;
}
