#include <windows.h>
#include <stdio.h>
static unsigned errors, command, sizes, scroll_code, scroll_position, scroll_axis, thumb_ends;
static LPARAM scroll_source;
#define CHECK(x) do {if(!(x)){++errors;printf("frame check failed line %u\n",__LINE__);}}while(0)
static LRESULT CALLBACK proc(HWND h,UINT m,WPARAM w,LPARAM l)
{
    if(m==WM_SIZE)++sizes;
    if(m==WM_HSCROLL || m==WM_VSCROLL) {
        scroll_axis=m;scroll_code=LOWORD(w);scroll_position=HIWORD(w);scroll_source=l;
        if(scroll_code==SB_THUMBPOSITION)++thumb_ends;
        return 0;
    }
    if(m==WM_COMMAND){command=LOWORD(w);return 0;}
    return DefWindowProcA(h,m,w,l);
}
int main(void)
{
    WNDCLASSA cls={0};RECT adjusted={0,0,160,120},client,outer,item;
    POINT origin={0,0};HDC dc,whole;HWND h,edit;BOOL valid;
    HMENU menu=CreateMenu(),popup=CreatePopupMenu();
    DWORD style=WS_CAPTION|WS_SYSMENU;
    cls.style=CS_OWNDC;
    cls.hInstance=GetModuleHandleA(0);cls.lpfnWndProc=proc;cls.lpszClassName="FrameTest";
    CHECK(RegisterClassA(&cls));CHECK(AppendMenuA(popup,MF_STRING,42,"Action"));
    CHECK(AppendMenuA(menu,MF_POPUP,(UINT)popup,"Game"));
    CHECK(AdjustWindowRect(&adjusted,style,TRUE));
    h=CreateWindowExA(0,cls.lpszClassName,"Title",style,10,20,adjusted.right-adjusted.left,adjusted.bottom-adjusted.top,0,menu,cls.hInstance,0);
    CHECK(h!=0);ShowWindow(h,SW_SHOW);UpdateWindow(h);
    CHECK(GetClientRect(h,&client));CHECK(client.right==160&&client.bottom==120);
    CHECK(GetWindowRect(h,&outer));CHECK(outer.left==10&&outer.top==20);
    CHECK(ClientToScreen(h,&origin));CHECK(origin.x==10-adjusted.left&&origin.y==20-adjusted.top);
    dc=GetDC(h);CHECK(SetPixel(dc,0,0,RGB(17,33,55))==RGB(17,33,55));
    whole=GetWindowDC(h);
    CHECK(GetPixel(whole,-adjusted.left,-adjusted.top)==RGB(17,33,55));
    ReleaseDC(h,whole);
    /* A window DC must not repoint the class-owned client DC. */
    CHECK(GetPixel(dc,0,0)==RGB(17,33,55));ReleaseDC(h,dc);
    CHECK(GetMenuItemRect(h,menu,0,&item));
    CHECK(item.top>=outer.top&&item.bottom<=origin.y);
    CHECK(SendMessageA(h,WM_NCHITTEST,0,MAKELPARAM(origin.x+3,origin.y+3))==HTCLIENT);
    CHECK(SendMessageA(h,WM_NCHITTEST,0,MAKELPARAM(item.left+2,item.top+2))==HTMENU);
    /* Drive the public non-client messages, then select the first popup row. */
    SendMessageA(h,WM_NCLBUTTONDOWN,HTMENU,MAKELPARAM(item.left+3,item.top+3));
    SendMessageA(h,WM_NCLBUTTONUP,HTMENU,MAKELPARAM(item.left+3,item.top+3));
    SendMessageA(h,WM_NCLBUTTONDOWN,HTMENU,MAKELPARAM(item.left+25,item.bottom+10));
    SendMessageA(h,WM_NCLBUTTONUP,HTMENU,MAKELPARAM(item.left+25,item.bottom+10));
    CHECK(command==42);
    /* Standard bars change the client area and share control interaction code. */
    {
        RECT before,after;unsigned old_sizes;HWND bar;
        CHECK(GetClientRect(h,&before));old_sizes=sizes;
        CHECK(ShowScrollBar(h,SB_BOTH,TRUE));
        CHECK(GetClientRect(h,&after));
        CHECK(after.right==before.right-16 && after.bottom==before.bottom-16);
        CHECK((GetWindowLongA(h,GWL_STYLE)&(WS_HSCROLL|WS_VSCROLL))==(WS_HSCROLL|WS_VSCROLL));
        CHECK(sizes==old_sizes+1);old_sizes=sizes;
        CHECK(ShowScrollBar(h,SB_BOTH,TRUE) && sizes==old_sizes);
        CHECK(SendMessageA(h,WM_NCHITTEST,0,MAKELPARAM(origin.x+after.right+8,origin.y+20))==HTVSCROLL);
        CHECK(SendMessageA(h,WM_NCHITTEST,0,MAKELPARAM(origin.x+20,origin.y+after.bottom+8))==HTHSCROLL);
        whole=GetWindowDC(h);
        CHECK(GetPixel(whole,origin.x-outer.left+after.right,origin.y-outer.top)==RGB(255,255,255));
        ReleaseDC(h,whole);
        SetScrollRange(h,SB_VERT,0,100,FALSE);SetScrollPos(h,SB_VERT,0,TRUE);
        SendMessageA(h,WM_NCLBUTTONDOWN,HTVSCROLL,MAKELPARAM(origin.x+after.right+8,origin.y+after.bottom-4));
        CHECK(GetCapture()==h && scroll_axis==WM_VSCROLL && scroll_code==SB_LINEDOWN && scroll_source==0);
        SendMessageA(h,WM_LBUTTONUP,0,MAKELPARAM(after.right+8,after.bottom-4));
        CHECK(GetCapture()==0 && scroll_code==SB_ENDSCROLL);
        SendMessageA(h,WM_NCLBUTTONDOWN,HTVSCROLL,MAKELPARAM(origin.x+after.right+8,origin.y+20));
        SendMessageA(h,WM_MOUSEMOVE,MK_LBUTTON,MAKELPARAM(after.right+8,64));
        CHECK(scroll_code==SB_THUMBTRACK && scroll_position>0 && scroll_position<=100);
        SendMessageA(h,WM_LBUTTONUP,0,MAKELPARAM(after.right+8,64));
        CHECK(thumb_ends==1 && scroll_code==SB_ENDSCROLL && GetCapture()==0);
        SetScrollPos(h,SB_HORZ,37,FALSE);
        SendMessageA(h,WM_NCLBUTTONDOWN,HTHSCROLL,MAKELPARAM(origin.x+4,origin.y+after.bottom+8));
        CHECK(scroll_axis==WM_HSCROLL && scroll_code==SB_LINELEFT);
        CHECK(ShowScrollBar(h,SB_HORZ,FALSE));CHECK(GetCapture()==0);
        CHECK(GetClientRect(h,&after) && after.right==before.right-16 && after.bottom==before.bottom);
        CHECK(GetScrollPos(h,SB_HORZ)==37);
        CHECK(ShowScrollBar(h,SB_BOTH,FALSE));
        CHECK(GetClientRect(h,&after) && EqualRect(&before,&after));
        CHECK(!ShowScrollBar(h,99,TRUE));CHECK(!ShowScrollBar((HWND)0x12345678,SB_BOTH,TRUE));
        bar=CreateWindowExA(0,"SCROLLBAR","",WS_CHILD|WS_VISIBLE,0,0,16,80,h,0,cls.hInstance,0);
        CHECK(bar && ShowScrollBar(bar,SB_CTL,FALSE) && !IsWindowVisible(bar));
        CHECK(ShowScrollBar(bar,SB_CTL,TRUE) && IsWindowVisible(bar));
        CHECK(DestroyWindow(bar));
    }
    edit=CreateWindowExA(0,"EDIT","",WS_CHILD|WS_VISIBLE,5,5,80,20,h,(HMENU)100,cls.hInstance,0);
    CHECK(edit!=0);CHECK(SetDlgItemInt(h,100,(UINT)-123,TRUE));
    CHECK((int)GetDlgItemInt(h,100,&valid,TRUE)==-123&&valid);
    CHECK(SetDlgItemTextA(h,100,"4294967296"));CHECK(GetDlgItemInt(h,100,&valid,FALSE)==0&&!valid);
    CHECK(SetDlgItemTextA(h,100,"-1"));CHECK(GetDlgItemInt(h,100,&valid,FALSE)==0&&!valid);
    CHECK(FindResourceA((HMODULE)0xdeadbeef,"missing",RT_MENU)==0);
    CHECK(DestroyWindow(h));
    printf("WINCALLBACK %s frame\n",errors?"FAIL":"PASS");return errors?1:0;
}
