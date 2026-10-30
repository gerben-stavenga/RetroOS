#include <windows.h>
#include <stdio.h>
static unsigned errors,mode,phase,commands,enters,exits,inits;
static HWND owner,first_popup;
static HMENU destroy_init;
#define CHECK(x) do {if(!(x)){++errors;printf("popup check failed line %u\n",__LINE__);}}while(0)
static LRESULT CALLBACK proc(HWND h,UINT m,WPARAM w,LPARAM l)
{
    if(m==WM_COMMAND){commands=LOWORD(w);return 0;}
    if(m==WM_ENTERMENULOOP)++enters;
    if(m==WM_EXITMENULOOP)++exits;
    if(m==WM_INITMENUPOPUP){++inits;CHECK(GetMenuItemCount((HMENU)w)>0);if((HMENU)w==destroy_init)DestroyMenu(destroy_init);}
    return DefWindowProcA(h,m,w,l);
}
static void CALLBACK choose(HWND h,UINT msg,UINT_PTR id,DWORD ticks)
{
    HWND popup=GetCapture();RECT r;
    CHECK(popup!=0 && popup!=owner);CHECK(GetWindowRect(popup,&r));
    CHECK(r.left>=400 && r.top>=300);
    if(mode==5 && phase==0){
        first_popup=popup;phase=1;
        PostMessageA(popup,WM_KEYDOWN,VK_DOWN,0);
        PostMessageA(popup,WM_KEYDOWN,VK_DOWN,0);
        PostMessageA(popup,WM_KEYDOWN,VK_RIGHT,0);
        return;
    }
    if(mode==5 && phase==1 && popup==first_popup)return;
    KillTimer(0,id);
    if(mode==5)CHECK(popup!=first_popup);
    if(mode==6){
        PostMessageA(popup,WM_KEYDOWN,VK_DOWN,0);
        PostMessageA(popup,WM_KEYDOWN,VK_DOWN,0);
        PostMessageA(popup,WM_KEYDOWN,VK_RIGHT,0);return;
    }
    if(mode==1){PostMessageA(popup,WM_KEYDOWN,VK_ESCAPE,0);return;}
    if(mode==2){
        PostMessageA(popup,WM_LBUTTONUP,0,MAKELPARAM(8,35));return;
    }
    if(mode==3){PostMessageA(popup,WM_LBUTTONDOWN,0,MAKELPARAM(-1,-1));return;}
    if(mode==4){DestroyWindow(owner);return;}
    /* A disabled row must not close the menu. */
    if(mode==0)PostMessageA(popup,WM_LBUTTONUP,0,MAKELPARAM(8,8));
    PostMessageA(popup,WM_KEYDOWN,VK_DOWN,0);
    PostMessageA(popup,WM_KEYDOWN,VK_RETURN,0);
}
static void start(unsigned which)
{
    mode=which;phase=0;CHECK(SetTimer(0,0,20,choose)!=0);
}
int main(void)
{
    WNDCLASSA cls={0};HMENU menu=CreatePopupMenu(),sub=CreatePopupMenu();MSG msg;
    cls.lpfnWndProc=proc;cls.hInstance=GetModuleHandleA(0);cls.lpszClassName="PopupTest";
    CHECK(RegisterClassA(&cls));
    owner=CreateWindowA(cls.lpszClassName,"owner",WS_POPUP|WS_VISIBLE,10,20,80,60,0,0,cls.hInstance,0);
    CHECK(owner!=0);
    CHECK(AppendMenuA(menu,MF_STRING|MF_GRAYED,11,"Disabled"));
    CHECK(AppendMenuA(menu,MF_SEPARATOR,0,0));
    CHECK(AppendMenuA(menu,MF_STRING,42,"&Play"));
    CHECK(AppendMenuA(sub,MF_STRING,77,"Child"));
    CHECK(AppendMenuA(menu,MF_POPUP,(UINT)sub,"More"));
    start(0);CHECK(TrackPopupMenu(menu,TPM_RETURNCMD|TPM_NONOTIFY,400,300,0,owner,0)==42);
    CHECK(commands==0 && enters==0 && exits==0 && inits==0 && GetCapture()==0);
    start(0);CHECK(TrackPopupMenu(menu,0,400,300,0,owner,0));
    CHECK(commands==0 && enters==1 && exits==1 && inits==1);
    CHECK(PeekMessageA(&msg,owner,WM_COMMAND,WM_COMMAND,PM_REMOVE));DispatchMessageA(&msg);
    CHECK(commands==42);commands=0;
    start(1);CHECK(TrackPopupMenu(menu,TPM_RETURNCMD,400,300,0,owner,0)==0);
    CHECK(GetCapture()==0);
    start(2);CHECK(TrackPopupMenu(menu,TPM_RETURNCMD,400,300,0,owner,0)==42);
    start(3);CHECK(TrackPopupMenu(menu,TPM_RETURNCMD,400,300,0,owner,0)==0);
    start(5);CHECK(TrackPopupMenu(menu,TPM_RETURNCMD,400,300,0,owner,0)==77);
    CHECK(enters==exits && GetCapture()==0);
    destroy_init=sub;start(6);CHECK(!TrackPopupMenu(menu,TPM_RETURNCMD,400,300,0,owner,0));
    CHECK(GetCapture()==0 && enters==exits);destroy_init=0;
    PostQuitMessage(17);CHECK(TrackPopupMenu(menu,TPM_RETURNCMD,400,300,0,owner,0)==0);
    CHECK(PeekMessageA(&msg,0,WM_QUIT,WM_QUIT,PM_REMOVE) && msg.wParam==17);
    CHECK(!TrackPopupMenu((HMENU)0x12345678,0,400,300,0,owner,0));
    start(4);CHECK(TrackPopupMenu(menu,TPM_RETURNCMD,400,300,0,owner,0)==0);
    CHECK(!IsWindow(owner) && GetCapture()==0);CHECK(DestroyMenu(menu));
    printf("WINCALLBACK %s popup\n",errors?"FAIL":"PASS");return errors?1:0;
}
