/* Native thread ABI adaptation. Execution and waits use RetroOS primitives. */
extern NTSTATUS WINAPI RetroThread(ULONG,const ULONG *,ULONG *);
extern void WINAPI RetroWineThreadStart(PRTL_THREAD_START_ROUTINE,void *);

NTSTATUS WINAPI RetroNtCreateThreadEx(HANDLE *handle,ACCESS_MASK access,OBJECT_ATTRIBUTES *attr,
    HANDLE process,PRTL_THREAD_START_ROUTINE entry,void *arg,ULONG flags,SIZE_T zero_bits,
    SIZE_T commit,SIZE_T reserve,PS_ATTRIBUTE_LIST *attributes)
{
    ULONG p[6]={(ULONG)RetroWineThreadStart,(ULONG)entry,(ULONG)arg,0,THREAD_CREATE_FLAGS_CREATE_SUSPENDED,0},out[8]={0};
    SIZE_T count=0,i; NTSTATUS status;
    if(process!=GetCurrentProcess()) return STATUS_NOT_SUPPORTED;
    if(!handle || !entry) return STATUS_INVALID_PARAMETER;
    if(zero_bits || (flags & ~THREAD_CREATE_FLAGS_CREATE_SUSPENDED)) return STATUS_NOT_SUPPORTED;
    if(attr && (attr->Length!=sizeof(*attr) || attr->ObjectName || attr->RootDirectory)) return STATUS_NOT_SUPPORTED;
    if(attributes){
        if(attributes->TotalLength<sizeof(SIZE_T) || (attributes->TotalLength-sizeof(SIZE_T))%sizeof(PS_ATTRIBUTE)) return STATUS_INVALID_PARAMETER;
        count=(attributes->TotalLength-sizeof(SIZE_T))/sizeof(PS_ATTRIBUTE);
        if(count>16) return STATUS_INVALID_PARAMETER;
        for(i=0;i<count;i++){
            PS_ATTRIBUTE *a=&attributes->Attributes[i];
            SIZE_T size=a->Attribute==PS_ATTRIBUTE_CLIENT_ID?sizeof(CLIENT_ID):a->Attribute==PS_ATTRIBUTE_TEB_ADDRESS?sizeof(TEB *):0;
            if(!size) return STATUS_NOT_SUPPORTED;
            if(a->Size!=size || !a->ValuePtr) return STATUS_INVALID_PARAMETER;
        }
    }
    if(!reserve) reserve=1024*1024;
    if(commit>reserve) reserve=commit;
    p[3]=reserve;
    status=RetroThread(0,p,out);
    if(status) return status;
    {
        TEB *teb=(TEB *)out[2];
        teb->ActivationContextStackPointer=&teb->ActivationContextStack;
        InitializeListHead(&teb->ActivationContextStack.FrameListCache);
        teb->RealClientId=teb->ClientId;
        teb->CurrentLocale=NtCurrentTeb()->CurrentLocale;
        teb->StaticUnicodeString.Buffer=teb->StaticUnicodeBuffer;
        teb->StaticUnicodeString.MaximumLength=sizeof(teb->StaticUnicodeBuffer);
    }
    *handle=ULongToHandle(out[0]);
    for(i=0;i<count;i++){
        PS_ATTRIBUTE *a=&attributes->Attributes[i];
        if(a->Attribute==PS_ATTRIBUTE_CLIENT_ID){CLIENT_ID *id=a->ValuePtr;id->UniqueProcess=ULongToHandle(out[3]);id->UniqueThread=ULongToHandle(out[1]);}
        else *(TEB **)a->ValuePtr=(TEB *)out[2];
        if(a->ReturnLength) *a->ReturnLength=a->Size;
    }
    if(!(flags & THREAD_CREATE_FLAGS_CREATE_SUSPENDED)) {
        ULONG resume[6]={out[0]},ignored[8];
        return RetroThread(1,resume,ignored);
    }
    return STATUS_SUCCESS;
}
NTSTATUS WINAPI RetroNtResumeThread(HANDLE handle,ULONG *previous)
{
    ULONG p[6]={(ULONG)handle},out[8]={0}; NTSTATUS status=RetroThread(1,p,out);
    if(!status && previous) *previous=out[0];return status;
}
NTSTATUS WINAPI RetroNtTerminateThread(HANDLE handle,NTSTATUS exit_code)
{
    ULONG p[6]={(ULONG)(handle?handle:GetCurrentThread()),exit_code},out[8]={0};
    return RetroThread(2,p,out);
}
NTSTATUS WINAPI RetroNtQueryInformationThread(HANDLE handle,THREADINFOCLASS class,void *buffer,ULONG size,ULONG *length)
{
    ULONG p[6]={(ULONG)handle},out[8]={0},needed; NTSTATUS status;
    if(class==ThreadBasicInformation) needed=sizeof(THREAD_BASIC_INFORMATION);
    else if(class==ThreadAmILastThread) needed=sizeof(ULONG);
    else return STATUS_INVALID_INFO_CLASS;
    if(length) *length=needed;
    if(size<needed) return STATUS_INFO_LENGTH_MISMATCH;
    if(!buffer) return STATUS_ACCESS_VIOLATION;
    status=RetroThread(3,p,out);if(status)return status;
    if(class==ThreadAmILastThread) *(ULONG *)buffer=out[4];
    else {
        THREAD_BASIC_INFORMATION *info=buffer;
        info->ExitStatus=out[0];info->TebBaseAddress=(TEB *)out[1];
        info->ClientId.UniqueProcess=ULongToHandle(out[2]);info->ClientId.UniqueThread=ULongToHandle(out[3]);
        info->AffinityMask=1;info->Priority=8;info->BasePriority=8;
    }
    return STATUS_SUCCESS;
}

extern NTSTATUS WINAPI RetroRestoreContext(const ULONG *);
extern NTSTATUS WINAPI RetroWineDispatchException(EXCEPTION_RECORD *,CONTEXT *);
NTSTATUS WINAPI RetroNtContinue(CONTEXT *context,BOOLEAN alertable)
{
    ULONG p[16];
    if(!context) return STATUS_INVALID_PARAMETER;
    if(alertable || (context->ContextFlags & 0x3f)!=7) return STATUS_NOT_SUPPORTED;
    p[0]=context->Edi;p[1]=context->Esi;p[2]=context->Ebx;p[3]=context->Edx;
    p[4]=context->Ecx;p[5]=context->Eax;p[6]=context->Ebp;p[7]=context->Eip;
    p[8]=context->Esp;p[9]=context->EFlags;p[10]=context->SegCs;p[11]=context->SegSs;
    p[12]=context->SegDs;p[13]=context->SegEs;p[14]=context->SegFs;p[15]=context->SegGs;
    return RetroRestoreContext(p);
}
void WINAPI RetroDispatchFault(const ULONG *p,ULONG code)
{
    CONTEXT context={0};EXCEPTION_RECORD record={0};
    context.ContextFlags=CONTEXT_CONTROL|CONTEXT_INTEGER|CONTEXT_SEGMENTS;
    context.Edi=p[0];context.Esi=p[1];context.Ebx=p[2];context.Edx=p[3];
    context.Ecx=p[4];context.Eax=p[5];context.Ebp=p[6];context.Eip=p[7];
    context.Esp=p[8];context.EFlags=p[9];context.SegCs=p[10];context.SegSs=p[11];
    context.SegDs=p[12];context.SegEs=p[13];context.SegFs=p[14];context.SegGs=p[15];
    record.ExceptionCode=code;record.ExceptionAddress=(void *)context.Eip;
    RetroWineDispatchException(&record,&context);
}
