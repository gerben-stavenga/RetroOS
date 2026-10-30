#include <windows.h>
#include <stdio.h>
#include <string.h>
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
    {
        typedef DWORD (WINAPI *Three)(DWORD,DWORD,DWORD);
        typedef DWORD (WINAPI *Four)(DWORD,DWORD,DWORD,DWORD);
        typedef DWORD (WINAPI *One)(DWORD);
        typedef DWORD (WINAPI *Five)(DWORD,DWORD,DWORD,DWORD,DWORD);
        Three open=(Three)GetProcAddress(mm,"OpenDriverA"),wide=(Three)GetProcAddress(mm,"OpenDriver"),close=(Three)GetProcAddress(mm,"CloseDriver");
        Four send=(Four)GetProcAddress(mm,"SendDriverMessage");
        One module=(One)GetProcAddress(mm,"GetDriverModuleHandle");
        Five def=(Five)GetProcAddress(mm,"DefDriverProc");
        unsigned m;
        CHECK(open && wide && close && send && module && def);
        if(!open || !wide || !close || !send || !module || !def)return 1;
        CHECK(open((DWORD)"missing.drv",0,0)==0 && wide((DWORD)L"missing.drv",0,0)==0);
        CHECK(!close(0x1234,0x12345678,0x87654321) && !send(0x1234,3,0x12345678,0x87654321) && !module(0x1234));
        for(m=0;m<16;m++)CHECK(def(0x12345678,0x1234,m,0x87654321,0)==(m==1 || m==2 || m==5 || m==6 || m==9 || m==10));
    }

    timer_set=(SetTimerFn)GetProcAddress(mm,"timeSetEvent");
    timer_kill=(KillTimerFn)GetProcAddress(mm,"timeKillEvent");
    CHECK(timer_set && timer_kill);if(!timer_set || !timer_kill)return 1;
    {
        typedef UINT (WINAPI *DeviceA)(LPCSTR);
        typedef UINT (WINAPI *DeviceW)(LPCWSTR);
        typedef BOOL (WINAPI *SetData)(UINT,DWORD);
        typedef DWORD (WINAPI *GetData)(UINT);
        typedef DWORD (WINAPI *Command)(UINT,UINT,DWORD,DWORD);
        typedef BOOL (WINAPI *ErrorA)(DWORD,LPSTR,UINT);
        typedef BOOL (WINAPI *ErrorW)(DWORD,LPWSTR,UINT);
        typedef DWORD (WINAPI *GetYield)(UINT,DWORD *);
        DeviceA device=(DeviceA)GetProcAddress(mm,"mciGetDeviceIDA");
        DeviceW device_w=(DeviceW)GetProcAddress(mm,"mciGetDeviceIDW");
        SetData set_data=(SetData)GetProcAddress(mm,"mciSetDriverData");
        GetData get_data=(GetData)GetProcAddress(mm,"mciGetDriverData");
        Command command=(Command)GetProcAddress(mm,"mciSendCommandA");
        ErrorA error=(ErrorA)GetProcAddress(mm,"mciGetErrorStringA");
        ErrorW error_w=(ErrorW)GetProcAddress(mm,"mciGetErrorStringW");
        GetYield yield=(GetYield)GetProcAddress(mm,"mciGetYieldProc");
        char text[64],short_text[5]={'x','x','x','x','!'};WCHAR wide[64];DWORD data=0x12345678,parms[5]={0};
        CHECK(device && device_w && set_data && get_data && command && error && error_w && yield);
        if(!device || !device_w || !set_data || !get_data || !command || !error || !error_w || !yield)return 1;
        CHECK(device("aLl")==0xffffffff && device_w(L"ALL")==0xffffffff);
        CHECK(device("alligator")==0 && device("civmovie")==0 && device(0)==0);
        CHECK(!set_data(1,0x12345678) && get_data(1)==0);
        CHECK(!yield(1,&data) && data==0x12345678);
        CHECK(command(0,0x803,0,0)==297);
        CHECK(command(0,0x803,0,(DWORD)parms)==266 && parms[1]==0);
        CHECK(command(1,0x806,0,(DWORD)parms)==257);
        CHECK(command(0xffffffff,0x804,0,0)==0);
        CHECK(error(266,text,sizeof(text)) && strlen(text)>0);
        CHECK(error_w(266,wide,64) && wide[0]=='T');
        CHECK(error(266,short_text,4) && short_text[3]==0 && short_text[4]=='!');
        CHECK(error(266,short_text,1) && short_text[0]==0);
        CHECK(!error(0xdeadbeef,text,sizeof(text)) && text[0]==0);
        CHECK(!error(266,0,32) && !error(266,short_text,0));
    }
    {
        typedef UINT (WINAPI *NumDevs)(void);
        typedef UINT (WINAPI *OpenWave)(DWORD*,UINT,void*,DWORD,DWORD,DWORD);
        typedef UINT (WINAPI *Caps)(UINT,void*,UINT);
        typedef UINT (WINAPI *ErrorText)(UINT,char*,UINT);
        typedef UINT (WINAPI *Header)(UINT,void*,UINT);
        typedef UINT (WINAPI *CloseWave)(UINT);
        typedef BOOL (WINAPI *Sound)(LPCWSTR,HMODULE,DWORD);
        NumDevs num=(NumDevs)GetProcAddress(mm,"waveOutGetNumDevs");
        OpenWave open=(OpenWave)GetProcAddress(mm,"waveOutOpen");
        Caps caps=(Caps)GetProcAddress(mm,"waveOutGetDevCapsA");
        ErrorText text=(ErrorText)GetProcAddress(mm,"waveOutGetErrorTextA");
        Header prepare=(Header)GetProcAddress(mm,"waveOutPrepareHeader");
        Header write=(Header)GetProcAddress(mm,"waveOutWrite");
        Header position=(Header)GetProcAddress(mm,"waveOutGetPosition");
        CloseWave close=(CloseWave)GetProcAddress(mm,"waveOutClose");
        Sound sound=(Sound)GetProcAddress(mm,"PlaySoundW");
        DWORD handle=0x12345678,buffer[16],original[16];
        char error[5]={'x','x','x','x','!'};
        CHECK(num && open && caps && text && prepare && write && position && close && sound);
        if(!num || !open || !caps || !text || !prepare || !write || !position || !close || !sound)return 1;
        memset(buffer,0x5a,sizeof(buffer));memcpy(original,buffer,sizeof(buffer));
        CHECK(num()==0);
        CHECK(open(&handle,0xffffffff,buffer,0,0,0)==6 && handle==0x12345678);
        CHECK(open(0,0xffffffff,buffer,0,0,1)==6); /* format query */
        CHECK(open(&handle,0,buffer,0,0,0)==2);
        CHECK(caps(0,buffer,sizeof(buffer))==2);
        CHECK(caps(0xffffffff,buffer,sizeof(buffer))==6);
        CHECK(caps(0,0,0)==0);
        CHECK(prepare(1,buffer,sizeof(buffer))==5);
        CHECK(write(1,buffer,sizeof(buffer))==5);
        CHECK(position(1,buffer,sizeof(buffer))==5 && close(1)==5);
        CHECK(memcmp(buffer,original,sizeof(buffer))==0);
        CHECK(text(6,error,4)==0 && error[3]==0 && error[4]=='!');
        CHECK(text(0xeeee,error,4)==9 && error[0]==0);
        CHECK(text(6,0,4)==11);
        CHECK(!sound(L"missing.wav",0,0));
    }
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
