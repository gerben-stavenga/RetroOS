#include <windows.h>
#include <stdio.h>
static unsigned errors;
static volatile unsigned calls,finished;
static DWORD main_id;
static HANDLE done,entered,release_callback;
typedef UINT (WINAPI *SetTimerFn)(UINT,UINT,DWORD,DWORD,UINT);
typedef UINT (WINAPI *KillTimerFn)(UINT);
static SetTimerFn timer_set;
static KillTimerFn timer_kill;
#define CHECK(x) do {if(!(x))++errors;}while(0)
#pragma off(check_stack)
static void CALLBACK tick(UINT id,UINT msg,DWORD user,DWORD a,DWORD b)
{
    CHECK(GetCurrentThreadId()!=main_id);
    CHECK(msg==0 && a==0 && b==0);CHECK(user==0x12345678);
    ++calls;SetEvent(done);
}
static void CALLBACK self_stop(UINT id,UINT msg,DWORD user,DWORD a,DWORD b)
{
    ++calls;CHECK(timer_kill(id)==0);SetEvent(done);
}
static void CALLBACK blocking(UINT id,UINT msg,DWORD user,DWORD a,DWORD b)
{
    SetEvent(entered);CHECK(WaitForSingleObject(release_callback,2000)==WAIT_OBJECT_0);
    finished=1;
}
static DWORD WINAPI unblock(LPVOID unused)
{
    Sleep(30);SetEvent(release_callback);return 0;
}
static void CALLBACK slow(UINT id,UINT msg,DWORD user,DWORD a,DWORD b)
{
    Sleep(15);
}
#pragma on(check_stack)
int main(void)
{
    HMODULE mm=LoadLibraryA("WINMM.DLL");UINT id,slow_id;HANDLE t;DWORD tid;unsigned count;
    CHECK(mm!=0);if(!mm)return 1;
    timer_set=(SetTimerFn)GetProcAddress(mm,"timeSetEvent");
    timer_kill=(KillTimerFn)GetProcAddress(mm,"timeKillEvent");
    CHECK(timer_set && timer_kill);if(!timer_set || !timer_kill)return 1;
    main_id=GetCurrentThreadId();done=CreateEventA(0,FALSE,FALSE,0);
    entered=CreateEventA(0,FALSE,FALSE,0);release_callback=CreateEventA(0,FALSE,FALSE,0);
    CHECK(!timer_set(0,0,(DWORD)tick,0,0));CHECK(!timer_set(1,0,0,0,0));
    CHECK(!timer_set(1,0,(DWORD)tick,0,0x8000));CHECK(timer_kill(0)==11);
    id=timer_set(10,1,(DWORD)tick,0x12345678,0);CHECK(id!=0);
    CHECK(WaitForSingleObject(done,2000)==WAIT_OBJECT_0);Sleep(30);CHECK(calls==1);
    CHECK(timer_kill(id)==11);
    id=timer_set(5,0,(DWORD)tick,0x12345678,0x101);CHECK(id!=0);
    CHECK(WaitForSingleObject(done,2000)==WAIT_OBJECT_0);
    CHECK(WaitForSingleObject(done,2000)==WAIT_OBJECT_0);
    CHECK(timer_kill(id)==0);count=calls;Sleep(30);CHECK(calls==count);
    ResetEvent(done);
    id=timer_set(5,0,(DWORD)self_stop,0,0x101);CHECK(id!=0);
    CHECK(WaitForSingleObject(done,2000)==WAIT_OBJECT_0);count=calls;Sleep(20);CHECK(calls==count);
    CHECK(timer_kill(id)==11);
    id=timer_set(5,0,(DWORD)done,0,0x10);CHECK(id!=0);
    CHECK(WaitForSingleObject(done,2000)==WAIT_OBJECT_0);Sleep(10);
    id=timer_set(5,0,(DWORD)blocking,0,0x101);CHECK(id!=0);
    CHECK(WaitForSingleObject(entered,2000)==WAIT_OBJECT_0);
    t=CreateThread(0,0,unblock,0,0,&tid);CHECK(t!=0);
    CHECK(timer_kill(id)==0);CHECK(finished==1);CloseHandle(t);
    slow_id=timer_set(1,0,(DWORD)slow,0,0x101);CHECK(slow_id!=0);
    id=timer_set(10,0,(DWORD)done,0,0x10);CHECK(id!=0);
    CHECK(WaitForSingleObject(done,2000)==WAIT_OBJECT_0);
    CHECK(timer_kill(slow_id)==0);
    CloseHandle(done);CloseHandle(entered);CloseHandle(release_callback);
    printf("WINCALLBACK %s multimedia (%u errors)\n",errors?"FAIL":"PASS",errors);
    return errors?1:0;
}
