/* RetroOS userspace implementation of Wine's user callback boundary. */
#include <stdarg.h>
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "ntuser.h"

struct callback_level {
    struct callback_level *next;
    void *reply;
    ULONG capacity, length;
    NTSTATUS status;
    ULONG jump[7];
};
struct callback_thread {
    struct callback_level *levels, *active;
};
static RTL_SRWLOCK callback_lock;
static ULONG callback_slot;
extern NTSTATUS WINAPI RetroWineDispatchCallback(void *,ULONG,ULONG);
extern int __attribute__((returns_twice)) RetroCallbackSave(ULONG *);
extern void __attribute__((noreturn)) RetroCallbackRestore(ULONG *);

static void WINAPI free_callbacks(void *value)
{
    struct callback_thread *thread=value;
    struct callback_level *level=thread->levels;
    while(level) {
        struct callback_level *next=level->next;
        if(level->reply) RtlFreeHeap(NtCurrentTeb()->Peb->ProcessHeap,0,level->reply);
        RtlFreeHeap(NtCurrentTeb()->Peb->ProcessHeap,0,level);
        level=next;
    }
    RtlFreeHeap(NtCurrentTeb()->Peb->ProcessHeap,0,thread);
}
static struct callback_thread *get_callbacks(BOOL create)
{
    struct callback_thread *thread=NULL;
    NTSTATUS status=STATUS_SUCCESS;
    RtlAcquireSRWLockExclusive(&callback_lock);
    if(!callback_slot && create) status=RtlFlsAlloc(free_callbacks,&callback_slot);
    RtlReleaseSRWLockExclusive(&callback_lock);
    if(status || !callback_slot) return NULL;
    RtlFlsGetValue(callback_slot,(void **)&thread);
    if(!thread && create) {
        thread=RtlAllocateHeap(NtCurrentTeb()->Peb->ProcessHeap,HEAP_ZERO_MEMORY,sizeof(*thread));
        if(thread && RtlFlsSetValue(callback_slot,thread)) {
            RtlFreeHeap(NtCurrentTeb()->Peb->ProcessHeap,0,thread);
            return NULL;
        }
    }
    return thread;
}
NTSTATUS WINAPI RetroUserCallback(ULONG id,const void *args,ULONG length,void **out,ULONG *size)
{
    struct callback_thread *thread;
    struct callback_level **slot, *level, *previous;
    if(id>=NtUserCallCount || !out || !size || (length && !args) || !NtCurrentTeb()->Peb->KernelCallbackTable)
        return STATUS_INVALID_PARAMETER;
    *out=NULL; *size=0;
    if(!(thread=get_callbacks(TRUE))) return STATUS_NO_MEMORY;
    previous=thread->active;
    slot=previous?&previous->next:&thread->levels;
    if(!*slot && !(*slot=RtlAllocateHeap(NtCurrentTeb()->Peb->ProcessHeap,HEAP_ZERO_MEMORY,sizeof(**slot))))
        return STATUS_NO_MEMORY;
    level=*slot;
    level->length=0;
    thread->active=level;
    if(!RetroCallbackSave(level->jump))
        level->status=RetroWineDispatchCallback((void *)args,length,id);
    thread->active=previous;
    *out=level->length?level->reply:NULL;
    *size=level->length;
    return level->status;
}
NTSTATUS WINAPI RetroNtCallbackReturn(void *data,ULONG length,NTSTATUS status)
{
    struct callback_thread *thread=get_callbacks(FALSE);
    struct callback_level *level;
    if(!thread || !(level=thread->active)) return STATUS_NO_CALLBACK_ACTIVE;
    if(length && !data) return STATUS_INVALID_PARAMETER;
    if(length>level->capacity) {
        void *reply=RtlAllocateHeap(NtCurrentTeb()->Peb->ProcessHeap,0,length);
        if(!reply) return STATUS_NO_MEMORY;
        if(level->reply) RtlFreeHeap(NtCurrentTeb()->Peb->ProcessHeap,0,level->reply);
        level->reply=reply; level->capacity=length;
    }
    /* The callback can return stack storage. Copy before unwinding its frame.
     * Each nesting level keeps its reply until the next callback at that level. */
    for(ULONG i=0;i<length;i++) ((volatile BYTE *)level->reply)[i]=((const BYTE *)data)[i];
    level->length=length; level->status=status;
    RetroCallbackRestore(level->jump);
}
