#define INCL_DOS
#define INCL_VIO
#define INCL_KBD
#include <os2.h>
#include <stdio.h>
#include <string.h>

#define CHECK(test) do { if (!(test)) { printf("OS2RUNTIME FAIL %u\n", __LINE__); return 1; } } while (0)
typedef ULONG (APIENTRY *PROBE)(void);
static unsigned char execute_buffer[] = {0xb8,42,0,0,0,0xc3};
static ULONG APIENTRY exception_handler(PEXCEPTIONREPORTRECORD report,
    PEXCEPTIONREGISTRATIONRECORD registration, PCONTEXTRECORD context, PVOID dispatcher) {
    return XCPT_CONTINUE_SEARCH;
}
int main(void) {
    ULONG disk, map, size, count, action, written;
    char cwd[260], error[260], text[16];
    HFILE file;
    HDIR find = HDIR_CREATE;
    FILEFINDBUF3 entry;
    FILESTATUS3 status;
    PVOID memory, shared;
    HMODULE module;
    PFN procedure;
    VIOMODEINFO mode;
    KBDINFO keyboard;
    TIB *tib; PIB *pib;
    EXCEPTIONREGISTRATIONRECORD first = {NULL, exception_handler};
    EXCEPTIONREGISTRATIONRECORD second = {NULL, exception_handler};
    PVOID old_chain;
    CHECK(((int (*)(void))execute_buffer)()==42);
    CHECK(DosSetMem((PVOID)((ULONG)execute_buffer & ~4095UL),4096,PAG_READ|PAG_WRITE|PAG_EXECUTE|PAG_COMMIT)==0);
    CHECK(((int (*)(void))execute_buffer)()==42);
    CHECK(DosQueryCurrentDisk(&disk, &map) == 0 && disk == 3 && (map & 4));
    size = sizeof(cwd);
    CHECK(DosQueryCurrentDir(0, cwd, &size) == 0 && strcmp(cwd, "OS2\\APPS") == 0);
    CHECK(DosGetInfoBlocks(&tib, &pib) == 0 && pib->pib_ultype == 2);
    old_chain = tib->tib_pexchain;
    CHECK(DosSetExceptionHandler(&first) == 0 && tib->tib_pexchain == &first);
    CHECK(DosSetExceptionHandler(&second) == 0 && tib->tib_pexchain == &second);
    CHECK(DosSetExceptionHandler(&second) == 87);
    CHECK(DosUnsetExceptionHandler(&first) == 0 && tib->tib_pexchain == &second);
    CHECK(DosUnsetExceptionHandler(&second) == 0 && tib->tib_pexchain == old_chain);
    CHECK(DosAllocMem(&memory, 8192, PAG_READ|PAG_WRITE|PAG_COMMIT) == 0);
    strcpy(memory, "committed");
    CHECK(DosSetMem(memory, 8192, PAG_READ|PAG_WRITE|PAG_COMMIT) == 0 && strcmp(memory, "committed") == 0);
    CHECK(DosAllocSharedMem(&shared,"\\SHAREMEM\\OS2PROBE",4096,PAG_READ|PAG_WRITE|PAG_COMMIT)==0);
    *(ULONG *)shared=0x12345678;
    CHECK(DosLoadModule(error,sizeof(error),"PROBE.DLL",&module)==0);
    CHECK(DosQueryProcAddr(module,0,"Probe",&procedure)==0 && ((PROBE)procedure)()==0x12345678);
    CHECK(DosQueryModuleName(module,sizeof(text),text)==111);
    CHECK(DosFreeModule(module)==0);
    CHECK(DosOpen("C:\\OS2\\APPS\\RUNTIME.TXT", &file, &action, 0, FILE_NORMAL,
         OPEN_ACTION_CREATE_IF_NEW|OPEN_ACTION_REPLACE_IF_EXISTS, OPEN_ACCESS_READWRITE|OPEN_SHARE_DENYNONE, NULL)==0);
    CHECK(DosWrite(file,"runtime",7,&written)==0 && written==7);
    CHECK(DosSetFilePtr(file,0,FILE_BEGIN,&written)==0);
    memset(text,0,sizeof(text));CHECK(DosRead(file,text,7,&written)==0 && written==7 && strcmp(text,"runtime")==0);
    CHECK(DosQueryFileInfo(file,FIL_STANDARD,&status,sizeof(status))==0 && status.cbFile==7);
    CHECK(DosClose(file)==0);
    CHECK(DosQueryPathInfo("C:\\OS2\\APPS\\RUNTIME.TXT",FIL_STANDARD,&status,sizeof(status))==0 && status.cbFile==7);
    count=1;CHECK(DosFindFirst("C:\\OS2\\APPS\\RUNTIME.T*",&find,0,&entry,sizeof(entry),&count,FIL_STANDARD)==0 && count==1 && entry.cbFile==7);
    count=1;CHECK(DosFindNext(find,&entry,sizeof(entry),&count)==18 && count==0);CHECK(DosFindClose(find)==0);
    CHECK(DosDelete("C:\\OS2\\APPS\\RUNTIME.TXT")==0);
    memset(&mode,0,sizeof(mode));mode.cb=sizeof(mode);
    CHECK(VioGetMode(&mode,0)==0 && mode.col==80 && mode.row==25);
    memset(&keyboard,0,sizeof(keyboard));keyboard.cb=sizeof(keyboard);
    CHECK(KbdGetStatus(&keyboard,0)==0 && keyboard.cb==10);
    CHECK(DosSleep(20)==0);
    CHECK(DosFreeMem(shared)==0 && DosFreeMem(memory)==0);
    puts("OS2RUNTIME PASS");
    return 0;
}
