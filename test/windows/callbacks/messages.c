#include <windows.h>
#include <stdio.h>
static volatile unsigned errors, lines[64], timer_calls, worker_done;
static DWORD main_id, worker_id;
static HWND main_window, worker_window;
static HANDLE ready, resume;
#define CHECK(x) do { if (!(x)) { unsigned n=errors++; if(n<64) lines[n]=__LINE__; } } while(0)
/* Raw CreateThread callbacks have no Watcom CRT thread data. */
#pragma off(check_stack)
static LRESULT CALLBACK proc(HWND h, UINT m, WPARAM w, LPARAM l)
{
    if(m==WM_APP) {
        CHECK(GetCurrentThreadId()==worker_id);
        CHECK(InSendMessage());
        return SendMessageA(main_window,WM_APP+1,w,l)+1;
    }
    if(m==WM_APP+1) {
        CHECK(GetCurrentThreadId()==main_id);
        CHECK(InSendMessage());
        return w+l;
    }
    if(m==WM_APP+2) {
        CHECK(GetCurrentThreadId()==worker_id);
        CHECK(ReplyMessage(91));
        CHECK(!ReplyMessage(92));
        CHECK(WaitForSingleObject(resume,2000)==WAIT_OBJECT_0);
        worker_done=1;
        return 93;
    }
    return DefWindowProcA(h,m,w,l);
}
static DWORD WINAPI worker(LPVOID unused)
{
    MSG m;
    worker_id=GetCurrentThreadId();
    worker_window=CreateWindowExA(0,"Messages","",WS_POPUP,0,0,20,20,0,0,0,0);
    CHECK(worker_window!=0);
    SetEvent(ready);
    while(GetMessageW(&m,0,0,0)>0) {
        if(m.hwnd==0 && m.message==WM_APP+5) {
            CHECK(m.wParam==77);
            CHECK(PostMessageA(main_window,WM_APP+6,88,99));
        } else if(m.hwnd==0 && m.message==WM_APP+7) {
            Sleep(20); CHECK(InvalidateRect(main_window,0,FALSE));
        } else DispatchMessageW(&m);
    }
    CHECK(m.wParam==42);
    CHECK(DestroyWindow(worker_window));
    return 0;
}
static void CALLBACK timer(HWND hwnd, UINT msg, UINT id, DWORD time)
{
    CHECK(GetCurrentThreadId()==main_id);
    CHECK(msg==WM_TIMER);
    ++timer_calls;
}
#pragma on(check_stack)
int main(void)
{
    WNDCLASSA c={0};
    MSG m, before;
    HANDLE thread;
    HWND child;
    UINT id, id2;
    unsigned i;
    DWORD start;
    main_id=GetCurrentThreadId();
    c.lpfnWndProc=proc; c.lpszClassName="Messages";
    CHECK(RegisterClassA(&c));
    main_window=CreateWindowExA(0,c.lpszClassName,"",WS_POPUP,0,0,20,20,0,0,0,0);
    child=CreateWindowExA(0,c.lpszClassName,"",WS_CHILD,0,0,10,10,main_window,0,0,0);
    CHECK(main_window && child);
    CHECK(!PeekMessageA(&m,0,0,0,PM_REMOVE));
    CHECK(!PostThreadMessageA(0xdead,WM_APP,0,0) && GetLastError()==1444);
    CHECK(PostMessageA(main_window,WM_APP+10,1,2));
    CHECK(PostMessageW(child,WM_APP+11,3,4));
    CHECK(PostThreadMessageW(main_id,WM_APP+12,5,6));
    CHECK(PeekMessageW(&m,(HWND)-1,0,0,PM_REMOVE) && m.message==WM_APP+12);
    CHECK(PeekMessageA(&m,main_window,WM_APP+11,WM_APP+11,PM_NOREMOVE) && m.hwnd==child);
    before=m;
    CHECK(PeekMessageW(&m,main_window,WM_APP+11,WM_APP+11,PM_REMOVE) && m.time==before.time && m.wParam==3);
    CHECK(GetMessageA(&m,0,0,0)==1 && m.message==WM_APP+10);
    CHECK(!PeekMessageW(&m,0,0,0,PM_REMOVE));
    CHECK(GetMessageW(&m,(HWND)0xdead,0,0)==-1 && GetLastError()==1400);
    PostQuitMessage(17);
    CHECK(PeekMessageA(&m,0,WM_APP,WM_APP,PM_NOREMOVE) && m.message==WM_QUIT);
    CHECK(GetMessageW(&m,0,WM_APP,WM_APP)==0 && m.wParam==17);
    CHECK(!PeekMessageA(&m,0,0,0,PM_REMOVE));
    id=SetTimer(0,0,20,timer); CHECK(id!=0);
    start=GetTickCount();
    CHECK(GetMessageW(&m,0,WM_TIMER,WM_TIMER)==1 && m.wParam==id);
    CHECK(GetTickCount()-start>=10);
    CHECK(!timer_calls);
    DispatchMessageW(&m); CHECK(timer_calls==1);
    CHECK(KillTimer(0,id));
    CHECK(!KillTimer(0,id));
    CHECK(!PeekMessageA(&m,0,WM_TIMER,WM_TIMER,PM_REMOVE));
    id=SetTimer(0,0,10,0); id2=SetTimer(0,0,10,0); CHECK(id && id2 && id!=id2);
    CHECK(KillTimer(0,id2));
    Sleep(30);
    CHECK(PeekMessageW(&m,0,WM_TIMER,WM_TIMER,PM_NOREMOVE) && m.wParam==id);
    CHECK(KillTimer(0,id));
    CHECK(PeekMessageA(&m,0,WM_TIMER,WM_TIMER,PM_REMOVE) && m.wParam==id);
    CHECK(!PeekMessageA(&m,0,WM_TIMER,WM_TIMER,PM_REMOVE));
    CHECK(SetTimer(child,71,10,0)==71);
    CHECK(SetTimer(child,71,1000,0)==71);
    Sleep(20); CHECK(!PeekMessageA(&m,0,WM_TIMER,WM_TIMER,PM_REMOVE));
    CHECK(DestroyWindow(child)); Sleep(20);
    CHECK(!PeekMessageA(&m,0,WM_TIMER,WM_TIMER,PM_REMOVE));
    ready=CreateEventA(0,0,0,0); resume=CreateEventA(0,0,0,0);
    thread=CreateThread(0,0,worker,0,0,0); CHECK(thread!=0);
    CHECK(WaitForSingleObject(ready,2000)==WAIT_OBJECT_0);
    CHECK(SendMessageW(worker_window,WM_APP,10,20)==31);
    CHECK(!InSendMessage()); CHECK(!ReplyMessage(1));
    CHECK(SendMessageA(worker_window,WM_APP+2,0,0)==91);
    CHECK(!worker_done); SetEvent(resume);
    CHECK(PostThreadMessageA(worker_id,WM_APP+5,77,0));
    CHECK(GetMessageA(&m,main_window,WM_APP+6,WM_APP+6)==1 && m.wParam==88 && m.lParam==99);
    CHECK(worker_done);
    ShowWindow(main_window,SW_SHOW);
    /* A fetched paint notification must not overtake subsequently posted work. */
    CHECK(PeekMessageA(&m,main_window,WM_PAINT,WM_PAINT,PM_NOREMOVE));
    CHECK(PostMessageA(main_window,WM_APP+20,0,0));
    CHECK(GetMessageA(&m,0,0,0)==1 && m.message==WM_APP+20);
    CHECK(GetMessageA(&m,main_window,WM_PAINT,WM_PAINT)==1);
    CHECK(PostThreadMessageA(worker_id,WM_APP+7,0,0));
    CHECK(GetMessageA(&m,main_window,WM_PAINT,WM_PAINT)==1);

    CHECK(PostThreadMessageA(worker_id,WM_QUIT,42,0));
    CHECK(WaitForSingleObject(thread,2000)==WAIT_OBJECT_0);
    CloseHandle(thread); CloseHandle(ready); CloseHandle(resume);
    CHECK(DestroyWindow(main_window));
    CHECK(UnregisterClassA(c.lpszClassName,0));
    for(i=0;i<errors && i<64;++i) printf("line %u failed\n",lines[i]);
    puts(errors?"WINCALLBACK FAIL":"WINCALLBACK PASS");
    return errors?1:0;
}
