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
    RESULTCODES child;
    CHECK(((int (*)(void))execute_buffer)()==42);
    CHECK(DosSetMem((PVOID)((ULONG)execute_buffer & ~4095UL),4096,PAG_READ|PAG_WRITE|PAG_EXECUTE|PAG_COMMIT)==0);
    CHECK(((int (*)(void))execute_buffer)()==42);
    CHECK(DosQueryCurrentDisk(&disk, &map) == 0 && disk == 3 && (map & 4));
    size = sizeof(cwd);
    CHECK(DosQueryCurrentDir(0, cwd, &size) == 0 && strcmp(cwd, "OS2\\APPS") == 0);
    /* Changing directories must store the resolved directory, not the input
       spelling: repeated parent/root operations must not grow separators. */
    for (count = 0; count < 4; ++count) {
        CHECK(DosSetCurrentDir("..\\\\") == 0);
        size = sizeof(cwd);
        CHECK(DosQueryCurrentDir(0, cwd, &size) == 0 && strcmp(cwd, "OS2") == 0);
        CHECK(DosSetCurrentDir(".\\apps\\\\") == 0);
        size = sizeof(cwd);
        CHECK(DosQueryCurrentDir(3, cwd, &size) == 0 && strcmp(cwd, "OS2\\APPS") == 0);
    }
    CHECK(DosSetCurrentDir("\\\\OS2\\\\APPS\\.") == 0);
    CHECK(DosSetCurrentDir("C:..") == 0);
    CHECK(DosSetCurrentDir("C:apps") == 0);
    CHECK(DosSetCurrentDir("..\\..\\..") == 0);
    size = sizeof(cwd);
    CHECK(DosQueryCurrentDir(0, cwd, &size) == 0 && cwd[0] == 0);
    CHECK(DosQueryPathInfo(".", FIL_QUERYFULLNAME, error, sizeof(error)) == 0 && strcmp(error, "C:\\") == 0);
    CHECK(DosSetCurrentDir("OS2") == 0);
    size = sizeof(cwd);
    CHECK(DosQueryCurrentDir(0, cwd, &size) == 0 && strcmp(cwd, "OS2") == 0);
    CHECK(DosSetCurrentDir("APPS") == 0);
    CHECK(DosSetCurrentDir("C:\\OS2\\APPS") == 0);
    {
        char path[] = "C:\\OS2\\APPS\\caf\x82.dat";
        const unsigned char binary[] = {0,0xff,0x82,0xc3,0x28};
        CHECK(DosOpen(path, &file, &action, 0, 0,
            OPEN_ACTION_CREATE_IF_NEW|OPEN_ACTION_REPLACE_IF_EXISTS,
            OPEN_ACCESS_READWRITE|OPEN_SHARE_DENYNONE, NULL) == 0);
        CHECK(DosWrite(file, (PVOID)binary, sizeof(binary), &written) == 0 && written == sizeof(binary));
        CHECK(DosClose(file) == 0);
        find = HDIR_CREATE;
        count = 1;
        CHECK(DosFindFirst("C:\\OS2\\APPS\\caf?.dat", &find, FILE_NORMAL,
            &entry, sizeof(entry), &count, FIL_STANDARD) == 0 && count == 1);
        CHECK(strcmp(entry.achName, "caf\x82.dat") == 0);
        CHECK(DosFindClose(find) == 0);
        CHECK(DosCreateDir("C:\\OS2\\APPS\\caf\x82", NULL) == 0 ||
            DosQueryPathInfo("C:\\OS2\\APPS\\caf\x82", FIL_STANDARD, &status, sizeof(status)) == 0);
        CHECK(DosSetCurrentDir("C:\\OS2\\APPS\\caf\x82") == 0);
        size = sizeof(cwd);
        CHECK(DosQueryCurrentDir(0, cwd, &size) == 0 && strcmp(cwd, "OS2\\APPS\\caf\x82") == 0 && size == 14);
        CHECK(DosSetCurrentDir("..") == 0);
    }
    {
        COUNTRYCODE country = {0, 0};
        COUNTRYINFO info;
        char letters[] = {'a', 0, 'z', (char)0x81, '!'};
        unsigned char collate[256];
        memset(&info, 0xcc, sizeof(info));
        CHECK(sizeof(info) == 44);
        CHECK(DosQueryCtryInfo(sizeof(info), &country, &info, &size) == 0 && size == 44);
        CHECK(info.country == 1 && info.codepage == 437 && info.fsDateFmt == 0);
        CHECK(strcmp(info.szCurrency, "$") == 0 && strcmp(info.szDecimal, ".") == 0);
        CHECK(DosMapCase(sizeof(letters), &country, letters) == 0);
        CHECK(letters[0] == 'A' && letters[1] == 0 && letters[2] == 'Z');
        CHECK((unsigned char)letters[3] == 0x9a && letters[4] == '!');
        CHECK(DosQueryCollate(sizeof(collate), &country, (char *)collate, &size) == 0 && size == 256);
        CHECK(collate['a'] == collate['A'] && collate['A'] < collate['Z']);
        ((unsigned char *)&info)[4] = 0xcc;
        CHECK(DosQueryCtryInfo(4, &country, &info, &size) == 399 && size == 4);
        CHECK(((unsigned char *)&info)[4] == 0xcc);
        country.codepage = 12345;
        CHECK(DosMapCase(sizeof(letters), &country, letters) == 472);
    }
    CHECK(DosGetInfoBlocks(&tib, &pib) == 0 && pib->pib_ultype == 2);
    CHECK(DosSearchPath(SEARCH_PATH, "C:\\MISSING;C:\\OS2\\APPS", "RUNTIME.EXE", (PBYTE)error, sizeof(error)) == 0);
    CHECK(strcmp(error, "C:\\OS2\\APPS\\RUNTIME.EXE") == 0);
    CHECK(DosSearchPath(SEARCH_PATH, "C:\\OS2\\APPS", "MISSING.EXE", (PBYTE)error, sizeof(error)) == 2);
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
    {
        FILESTATUS3L large_status;
        FILEFINDBUF3L large_find;
        HDIR large_handle=HDIR_CREATE;
        CHECK(DosQueryFileInfo(file,FIL_STANDARDL,&large_status,sizeof(large_status))==0 && large_status.cbFile.ulLo==7 && large_status.cbFile.ulHi==0);
        CHECK(DosQueryPathInfo("C:\\OS2\\APPS\\RUNTIME.TXT",FIL_STANDARDL,&large_status,sizeof(large_status))==0 && large_status.cbFile.ulLo==7 && large_status.cbFile.ulHi==0);
        count=1;
        CHECK(DosFindFirst("C:\\OS2\\APPS\\RUNTIME.T*",&large_handle,0,&large_find,sizeof(large_find),&count,FIL_STANDARDL)==0 && count==1);
        CHECK(large_find.cbFile.ulLo==7 && large_find.cbFile.ulHi==0 && strcmp(large_find.achName,"RUNTIME.TXT")==0);
        CHECK(DosFindClose(large_handle)==0);
    }
    CHECK(DosClose(file)==0);
    CHECK(DosQueryPathInfo("C:\\OS2\\APPS\\RUNTIME.TXT",FIL_STANDARD,&status,sizeof(status))==0 && status.cbFile==7);
    count=1;CHECK(DosFindFirst("C:\\OS2\\APPS\\RUNTIME.T*",&find,0,&entry,sizeof(entry),&count,FIL_STANDARD)==0 && count==1 && entry.cbFile==7);
    count=1;CHECK(DosFindNext(find,&entry,sizeof(entry),&count)==18 && count==0);CHECK(DosFindClose(find)==0);
    CHECK(DosOpen("C:\\OS2\\APPS\\RUNTIME.TXT", &file, &action, 0, FILE_NORMAL,
         OPEN_ACTION_OPEN_IF_EXISTS, OPEN_ACCESS_READWRITE|OPEN_SHARE_DENYNONE, NULL)==0);
    CHECK(DosSetFilePtr(file,5,FILE_BEGIN,&written)==0 && written==5);
    CHECK(DosSetFileSize(file,3)==0);
    CHECK(DosSetFilePtr(file,0,FILE_CURRENT,&written)==0 && written==5);
    CHECK(DosQueryFileInfo(file,FIL_STANDARD,&status,sizeof(status))==0 && status.cbFile==3);
    {
        typedef ULONG (APIENTRY *SETSIZEL)(HFILE, ULONG, ULONG);
        CHECK(DosQueryModuleHandle("DOSCALLS",&module)==0);
        CHECK(DosQueryProcAddr(module,989,NULL,&procedure)==0);
        CHECK(((SETSIZEL)procedure)(file,8193,0)==0);
        CHECK(((SETSIZEL)procedure)(file,1,1)==87);
    }
    CHECK(DosSetFilePtr(file,0,FILE_CURRENT,&written)==0 && written==5);
    CHECK(DosSetFilePtr(file,0,FILE_BEGIN,&written)==0);
    memset(text,0xcc,sizeof(text));
    CHECK(DosRead(file,text,8,&written)==0 && written==8 && memcmp(text,"run\0\0\0\0\0",8)==0);
    CHECK(DosSetFilePtr(file,8192,FILE_BEGIN,&written)==0);
    CHECK(DosRead(file,text,2,&written)==0 && written==1 && text[0]==0);
    CHECK(DosSetFileSize(file,0)==0 && DosClose(file)==0);
    CHECK(DosQueryPathInfo("C:\\OS2\\APPS\\RUNTIME.TXT",FIL_STANDARD,&status,sizeof(status))==0 && status.cbFile==0);
    memset(&status,0,sizeof(status)); status.attrFile=FILE_ARCHIVED|FILE_HIDDEN;
    CHECK(DosSetPathInfo("C:\\OS2\\APPS\\RUNTIME.TXT",FIL_STANDARD,&status,sizeof(status),0)==0);
    CHECK(DosQueryPathInfo("C:\\OS2\\APPS\\RUNTIME.TXT",FIL_STANDARD,&status,sizeof(status))==0 && status.attrFile==(FILE_ARCHIVED|FILE_HIDDEN));
    memset(&status,0,sizeof(status)); status.attrFile=FILE_ARCHIVED;
    CHECK(DosSetPathInfo("C:\\OS2\\APPS\\RUNTIME.TXT",FIL_STANDARD,&status,sizeof(status),0)==0);
    CHECK(DosSetFileSize(0xffffffffUL,7)==6);
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
