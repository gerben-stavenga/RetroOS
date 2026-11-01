/* Process ABI translation; execution uses RetroOS's shared binary loader. */
extern LONG WINAPI RetroSpawnProcess(const ULONG *);
extern NTSTATUS WINAPI RetroChild(ULONG,ULONG,const ULONG *,ULONG *);
NTSTATUS WINAPI RetroNtCreateUserProcess(HANDLE *process,HANDLE *thread,ACCESS_MASK process_access,
    ACCESS_MASK thread_access,OBJECT_ATTRIBUTES *process_attr,OBJECT_ATTRIBUTES *thread_attr,
    ULONG process_flags,ULONG thread_flags,RTL_USER_PROCESS_PARAMETERS *params,
    PS_CREATE_INFO *create,PS_ATTRIBUTE_LIST *attributes)
{
    ULONG p[8],handles[2],ignored=0;
    SIZE_T count=0,i,envlen=0;
    const WCHAR *environment;
    LONG pid;NTSTATUS status;
    if(!process || !thread || !params || !create || !(params->Flags & PROCESS_PARAMS_FLAG_NORMALIZED))
        return STATUS_INVALID_PARAMETER;
    if(process_flags & ~(PROCESS_CREATE_FLAGS_SUSPENDED | PROCESS_CREATE_FLAGS_NO_DEBUG_INHERIT) ||
       thread_flags!=THREAD_CREATE_FLAGS_CREATE_SUSPENDED) return STATUS_NOT_SUPPORTED;
    if((process_attr && (process_attr->ObjectName || process_attr->RootDirectory)) ||
       (thread_attr && (thread_attr->ObjectName || thread_attr->RootDirectory))) return STATUS_NOT_SUPPORTED;
    if(attributes){
        if(attributes->TotalLength<sizeof(SIZE_T) ||
            (attributes->TotalLength-sizeof(SIZE_T))%sizeof(PS_ATTRIBUTE)) return STATUS_INVALID_PARAMETER;
        count=(attributes->TotalLength-sizeof(SIZE_T))/sizeof(PS_ATTRIBUTE);
        if(count>16) return STATUS_INVALID_PARAMETER;
        for(i=0;i<count;i++) {
            PS_ATTRIBUTE *a=&attributes->Attributes[i];
            if(a->Attribute!=PS_ATTRIBUTE_IMAGE_NAME && a->Attribute!=PS_ATTRIBUTE_CLIENT_ID &&
               a->Attribute!=PS_ATTRIBUTE_IMAGE_INFO) return STATUS_NOT_SUPPORTED;
            if(!a->ValuePtr || (a->Attribute==PS_ATTRIBUTE_CLIENT_ID && a->Size!=sizeof(CLIENT_ID)) ||
               (a->Attribute==PS_ATTRIBUTE_IMAGE_INFO && a->Size!=sizeof(SECTION_IMAGE_INFORMATION)))
                return STATUS_INVALID_PARAMETER;
        }
    }
    environment=params->Environment?params->Environment:NtCurrentTeb()->Peb->ProcessParameters->Environment;
    if(environment){
        for(envlen=0;envlen<32767;envlen++) if(!environment[envlen] && !environment[envlen+1]) break;
        if(envlen==32767) return STATUS_INVALID_PARAMETER;
        envlen+=2;
    }
    p[0]=(ULONG)params->ImagePathName.Buffer;p[1]=params->ImagePathName.Length;
    p[2]=(ULONG)params->CommandLine.Buffer;p[3]=params->CommandLine.Length;
    p[4]=(ULONG)params->CurrentDirectory.DosPath.Buffer;p[5]=params->CurrentDirectory.DosPath.Length;
    p[6]=(ULONG)environment;p[7]=envlen*sizeof(WCHAR);
    pid=RetroSpawnProcess(p);
    if(pid<0){
        RetroChild(3,0,NULL,&ignored);
        return pid==-2?STATUS_OBJECT_NAME_NOT_FOUND:pid==-22?STATUS_INVALID_PARAMETER:STATUS_INVALID_IMAGE_FORMAT;
    }
    status=RetroChild(0,pid,NULL,handles);if(status) return status;
    *process=ULongToHandle(handles[0]);*thread=ULongToHandle(handles[1]);
    memset(create,0,sizeof(*create));create->Size=sizeof(*create);create->State=PsCreateSuccess;
    for(i=0;i<count;i++) {
        PS_ATTRIBUTE *a=&attributes->Attributes[i];
        if(a->Attribute==PS_ATTRIBUTE_CLIENT_ID){
            CLIENT_ID *id=a->ValuePtr;id->UniqueProcess=ULongToHandle(pid);id->UniqueThread=ULongToHandle(pid);
        }else if(a->Attribute==PS_ATTRIBUTE_IMAGE_INFO){
            SECTION_IMAGE_INFORMATION *image=a->ValuePtr;
            memset(image,0,sizeof(*image));image->Machine=IMAGE_FILE_MACHINE_I386;
        }
        if(a->ReturnLength) *a->ReturnLength=a->Size;
    }
    return STATUS_SUCCESS;
}
