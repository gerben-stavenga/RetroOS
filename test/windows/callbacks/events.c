#include <windows.h>
#include <stdio.h>
static unsigned errors;
#define CHECK(x) do { if (!(x)) { ++errors; printf("event check failed line %u\n", __LINE__); } } while(0)
static HANDLE events[2];
#pragma off(check_stack)
static DWORD WINAPI signal_both(LPVOID unused)
{
    Sleep(10);
    SetEvent(events[1]);
    Sleep(10);
    SetEvent(events[0]);
    return 17;
}
#pragma on(check_stack)
int main(void)
{
    HANDLE alias, thread;
    DWORD id;
    events[0] = CreateEventA(0, FALSE, FALSE, "named event");
    events[1] = CreateEventA(0, TRUE, FALSE, 0);
    CHECK(events[0] && events[1]);
    alias = OpenEventA(EVENT_ALL_ACCESS, FALSE, "named event");
    CHECK(alias != 0);
    CHECK(WaitForMultipleObjects(2,events,FALSE,0)==WAIT_TIMEOUT);
    SetEvent(alias);
    CHECK(WaitForMultipleObjects(2,events,TRUE,0)==WAIT_TIMEOUT);
    /* An unsuccessful wait-all must not consume an auto-reset signal. */
    CHECK(WaitForSingleObject(events[0],0)==WAIT_OBJECT_0);
    CHECK(WaitForSingleObject(alias,0)==WAIT_TIMEOUT);
    CHECK(CloseHandle(alias));
    CHECK(SetEvent(events[0]));
    CHECK(WaitForMultipleObjects(2,events,FALSE,0)==WAIT_OBJECT_0);
    thread=CreateThread(0,0,signal_both,0,0,&id);
    CHECK(thread!=0);
    CHECK(WaitForMultipleObjects(2,events,TRUE,2000)==WAIT_OBJECT_0);
    CHECK(WaitForSingleObject(events[0],0)==WAIT_TIMEOUT);
    CHECK(WaitForSingleObject(events[1],0)==WAIT_OBJECT_0);
    CHECK(ResetEvent(events[1]));
    CHECK(WaitForSingleObject(events[1],0)==WAIT_TIMEOUT);
    CHECK(WaitForSingleObject(thread,2000)==WAIT_OBJECT_0);
    CHECK(CloseHandle(events[0]));
    CHECK(OpenEventA(EVENT_ALL_ACCESS,FALSE,"named event")==0);
    CHECK(CloseHandle(events[1]));
    printf("WINCALLBACK %s events\n",errors?"FAIL":"PASS");
    return errors?1:0;
}
