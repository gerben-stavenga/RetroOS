#include <windows.h>
#include <stdio.h>
#include <string.h>

static DWORD slot;
static HANDLE event;
static volatile LONG shared;
static CRITICAL_SECTION lock;
static unsigned char thunk[] = {0xb8,42,0,0,0,0xc3};

/* Raw CreateThread callbacks do not initialize the Watcom CRT thread data. */
#pragma off(check_stack)
static DWORD WINAPI worker(LPVOID parameter)
{
    unsigned short rounding;
    _asm { fnstcw rounding }
    rounding = (rounding & ~0x0c00) | 0x0c00;
    _asm { fldcw rounding }
    if (TlsGetValue(slot) != NULL || GetCurrentThreadId() == (DWORD)parameter)
        return 91;
    EnterCriticalSection(&lock);
    TlsSetValue(slot, (LPVOID)123);
    shared = 42;
    Sleep(5);
    _asm { fnstcw rounding }
    if ((rounding & 0x0c00) != 0x0c00) return 93;
    if (TlsGetValue(slot) != (LPVOID)123)
        return 92;
    LeaveCriticalSection(&lock);
    SetEvent(event);
    return 7;
}

#pragma on(check_stack)
int main(void)
{
    const char *plugins[] = {"SCRRES.DLL", "DESCSS.DLL", "NDNPASS.DLL", "TETRIS.DLL"};
    unsigned i;
    HANDLE task, mapping, opened;
    DWORD *view, *alias;
    DWORD id, code, old, restored;
    unsigned short rounding, original;
    DWORD (*execute_thunk)(void);
    HMODULE module;
    DWORD (WINAPI *probe)(void);
    DWORD (WINAPI *console_cp)(void);
    BOOL (WINAPI *set_security)(LPCSTR, DWORD, void *);
    char env[128];
    char cwd[128];
    int (__cdecl *crt_chdir)(const char *);
    char *(__cdecl *crt_getcwd)(char *, int);
    WCHAR wide_env[16];
    if (!SetEnvironmentVariableA("RETRO_ENV_PROBE", "value")) return 18;
    if (GetEnvironmentVariableA("retro_env_probe", NULL, 0) != 6) return 19;
    env[0] = '!';
    if (GetEnvironmentVariableA("RETRO_ENV_PROBE", env, 5) != 6 || env[0] != '!') return 20;
    if (GetEnvironmentVariableA("RETRO_ENV_PROBE", env, sizeof(env)) != 5 ||
        strcmp(env, "value")) return 21;
    if (GetEnvironmentVariableW(L"RETRO_ENV_PROBE", wide_env, 16) != 5 ||
        wide_env[0] != 'v' || wide_env[5] != 0) return 22;
    if (!SetEnvironmentVariableA("RETRO_ENV_PROBE", "") ||
        GetEnvironmentVariableA("RETRO_ENV_PROBE", NULL, 0) != 1) return 23;
    if (!SetEnvironmentVariableA("RETRO_ENV_PROBE", NULL)) return 24;
    if (GetEnvironmentVariableA("RETRO_ENV_PROBE", env, sizeof(env)) != 0 ||
        GetLastError() != 203) return 25;
    /* MSVCRT _chdir records drive paths in hidden '=C:' environment entries. */
    if (!SetEnvironmentVariableA("=C:", "C:\\first") ||
        !SetEnvironmentVariableW(L"=D:", L"D:\\other")) return 70;
    if (GetEnvironmentVariableA("=c:", env, sizeof(env)) != 8 ||
        strcmp(env, "C:\\first")) return 71;
    if (!SetEnvironmentVariableW(L"=c:", L"C:\\second") ||
        GetEnvironmentVariableA("=C:", env, sizeof(env)) != 9 ||
        strcmp(env, "C:\\second")) return 72;
    if (!SetEnvironmentVariableA("=C:", NULL) ||
        GetEnvironmentVariableA("=C:", env, sizeof(env)) != 0 ||
        GetLastError() != 203) return 73;
    if (GetEnvironmentVariableA("=D:", env, sizeof(env)) != 8 ||
        strcmp(env, "D:\\other")) return 74;
    if (SetEnvironmentVariableA("bad=name", "value") ||
        GetLastError() != ERROR_INVALID_PARAMETER) return 75;
    SetEnvironmentVariableW(L"=D:", NULL);
    if (!GetCurrentDirectoryA(sizeof(cwd), cwd)) return 76;
    module = LoadLibraryA("MSVCRT.DLL");
    crt_chdir = (int (__cdecl *)(const char *))GetProcAddress(module, "_chdir");
    crt_getcwd = (char *(__cdecl *)(char *, int))GetProcAddress(module, "_getcwd");
    if (!crt_chdir || !crt_getcwd) return 77;
    if (crt_chdir("C:\\RETROOS\\WINDOWS\\SYSTEM32") != 0 ||
        crt_getcwd(env, sizeof(env)) != env ||
        strcmp(env, "C:\\RETROOS\\WINDOWS\\SYSTEM32")) return 78;
    if (GetEnvironmentVariableA("=C:", env, sizeof(env)) != 27 ||
        strcmp(env, "C:\\RETROOS\\WINDOWS\\SYSTEM32")) return 79;
    if (crt_chdir(cwd) != 0 || crt_getcwd(env, sizeof(env)) != env ||
        strcmp(env, cwd)) return 80;
    FreeLibrary(module);
    {
        STARTUPINFOA startup;
        PROCESS_INFORMATION child;
        char command[128];
        const char *programs[] = {"WINCHILD.EXE", "OS2CHILD.EXE"};
        if (!SetCurrentDirectoryA("C:\\WORK")) return 83;
        memset(&startup, 0, sizeof(startup));
        startup.cb = sizeof(startup);
        for (i = 0; i < 4; ++i) {
            sprintf(command, "C:\\RETROOS\\COMMAND.COM /c C:\\APPS\\%s", programs[i % 2]);
            if (!CreateProcessA(i < 2 ? "C:\\RETROOS\\COMMAND.COM" : NULL,
                    command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &child)) return 81;
            if (WaitForSingleObject(child.hProcess, 5000) != WAIT_OBJECT_0 ||
                !GetExitCodeProcess(child.hProcess, &code) || code != 0) return 82;
            CloseHandle(child.hThread);
            CloseHandle(child.hProcess);
        }
    }
    if (!SetCurrentDirectoryA(cwd)) return 84;
    module = LoadLibraryA("ADVAPI32.DLL");
    set_security = (BOOL (WINAPI *)(LPCSTR, DWORD, void *))GetProcAddress(module, "SetFileSecurityA");
    if (!set_security) { printf("Security export missing, module %lu error %lu\n", (DWORD)module, GetLastError()); return 26; }
    if (set_security("WINTHREAD.EXE", 4, NULL) || GetLastError() != 50) {
        printf("Security result mismatch, error %lu\n", GetLastError()); return 26;
    }
    if (!VirtualProtect(thunk, sizeof(thunk), PAGE_EXECUTE_READ, &old) ||
        old != PAGE_READWRITE) return 10;
    execute_thunk = (DWORD (*)(void))thunk;
    if (execute_thunk() != 42 ||
        !VirtualProtect(thunk, sizeof(thunk), old, &restored) ||
        restored != PAGE_EXECUTE_READ) return 11;
    _asm { fnstcw original }
    InitializeCriticalSection(&lock);
    Sleep(1);
    slot = TlsAlloc();
    TlsSetValue(slot, (LPVOID)456);
    event = CreateEventA(NULL, FALSE, FALSE, NULL);
    task = CreateThread(NULL, 0, worker, (LPVOID)GetCurrentThreadId(),
                        CREATE_SUSPENDED, &id);
    if (!task || !id || WaitForSingleObject(event, 0) != WAIT_TIMEOUT)
        return 1;
    EnterCriticalSection(&lock);
    if (ResumeThread(task) != 1) return 2;
    Sleep(2);
    if (shared != 0) return 8;
    LeaveCriticalSection(&lock);
    if (WaitForSingleObject(event, 5000) != WAIT_OBJECT_0) return 2;
    _asm { fnstcw rounding }
    if (rounding != original) return 12;
    if (shared != 42 || TlsGetValue(slot) != (LPVOID)456)
        return 3;
    if (WaitForSingleObject(task, 5000) != WAIT_OBJECT_0 ||
        !GetExitCodeThread(task, &code) || code != 7)
        return 4;
    if (WaitForSingleObject(event, 0) != WAIT_TIMEOUT)
        return 5;
    mapping = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
                                 0, 32768, "WINTHREAD_SHARED_HEAP");
    if (!mapping) return 14;
    view = (DWORD *)MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, 32768);
    if (!view) return 15;
    view[0] = 123456;
    opened = OpenFileMappingA(FILE_MAP_WRITE, FALSE, "WINTHREAD_SHARED_HEAP");
    alias = (DWORD *)MapViewOfFile(opened, FILE_MAP_WRITE, 0, 0, 0);
    if (!opened || !alias || alias[0] != 123456) return 16;
    UnmapViewOfFile(alias);
    UnmapViewOfFile(view);
    CloseHandle(opened);
    CloseHandle(mapping);
    module = GetModuleHandleA("KERNEL32.DLL");
    console_cp = (DWORD (WINAPI *)(void))GetProcAddress(module, "GetConsoleOutputCP");
    if (!console_cp || console_cp() != 437) return 13;
    module = LoadLibraryA("PROBE.DLL");
    if (!module) return 6;
    probe = (DWORD (WINAPI *)(void))GetProcAddress(module, "ProbeValue");
    if (!probe || probe() != 1 || !FreeLibrary(module)) return 7;
    for (i = 0; i < sizeof(plugins) / sizeof(plugins[0]); ++i) {
        if (GetFileAttributesA(plugins[i]) == INVALID_FILE_ATTRIBUTES) continue;
        module = LoadLibraryA(plugins[i]);
        if (!module || !GetProcAddress(module, "#CatchCommand#")) {
            printf("Plugin load failed: %s, error %lu\n", plugins[i], GetLastError());
            return 17;
        }
        printf("%s LOAD PASS\n", plugins[i]);
    }
    puts("WINTHREAD PASS");
    return 0;
}
