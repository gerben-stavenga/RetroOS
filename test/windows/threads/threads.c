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
    {
        const WCHAR unicode[] = {0x00e9, 0x0416, 0xd83d, 0xde00, 0};
        const char utf8[] = "\xc3\xa9\xd0\x96\xf0\x9f\x98\x80";
        const WCHAR path[] = {'C',':','\\','A','P','P','S','\\',0x00e9,0x0416,0xd83d,0xde00,'.','t','x','t',0};
        const unsigned char binary[] = {0,0xff,0x82,0xc3,0x28};
        WCHAR wide[32];
        WORD types[6];
        char converted[32], saved_cwd[128];
        BOOL used;
        DWORD n;
        HANDLE file, search;
        WIN32_FIND_DATAW found;
        CHAR_INFO cell;
        COORD one = {1,1}, origin = {0,0};
        SMALL_RECT rect = {0,0,0,0};
        if (MultiByteToWideChar(65001, 8, utf8, -1, NULL, 0) != 5 ||
            MultiByteToWideChar(65001, 8, utf8, -1, wide, 32) != 5 ||
            memcmp(wide, unicode, sizeof(unicode))) return 100;
        memset(converted, '!', sizeof(converted));
        if (WideCharToMultiByte(65001, 0, unicode, -1, converted, 8, NULL, NULL) ||
            GetLastError() != ERROR_INSUFFICIENT_BUFFER || converted[0] != '!') return 101;
        if (WideCharToMultiByte(65001, 0, unicode, -1, converted, 32, NULL, NULL) != 9 ||
            strcmp(converted, utf8)) return 102;
        if (MultiByteToWideChar(1252, 0, "\xe9\x80", 2, wide, 32) != 2 ||
            wide[0] != 0xe9 || wide[1] != 0x20ac) return 103;
        if (MultiByteToWideChar(1251, 0, "\xc6", 1, wide, 32) != 1 || wide[0] != 0x0416) return 104;
        if (MultiByteToWideChar(65001, 8, "\xff", 1, wide, 32) || GetLastError() != 1113) return 105;
        if (WideCharToMultiByte(1252, 0, unicode, 2, converted, 32, NULL, &used) != 2 ||
            (unsigned char)converted[0] != 0xe9 || converted[1] != '?' || !used) return 106;
        memset(types, 0xcc, sizeof(types));
        if (!GetStringTypeW(CT_CTYPE1, unicode, 4, types) ||
            !(types[0] & C1_LOWER) || !(types[1] & C1_UPPER) || types[4] != 0xcccc) return 117;
        if (!GetStringTypeA(LOCALE_USER_DEFAULT, CT_CTYPE1, "\xe9", 1, types) ||
            !(types[0] & C1_LOWER) || types[1] != (C1_UPPER|C1_ALPHA)) return 118;
        if (!OemToCharBuffA("caf\x82", converted, 4) || memcmp(converted, "caf\xe9", 4) ||
            !CharToOemBuffA("caf\xe9", converted, 4) || memcmp(converted, "caf\x82", 4)) return 119;
        if (!SetEnvironmentVariableW(L"UNICODE_PROBE", unicode) ||
            GetEnvironmentVariableW(L"UNICODE_PROBE", NULL, 0) != 5 ||
            GetEnvironmentVariableW(L"UNICODE_PROBE", wide, 32) != 4 ||
            memcmp(wide, unicode, sizeof(unicode))) return 107;
        file = CreateFileW(path, GENERIC_READ|GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (file == INVALID_HANDLE_VALUE || !WriteFile(file, binary, sizeof(binary), &n, NULL) ||
            n != sizeof(binary) || !CloseHandle(file)) return 108;
        if (GetFileAttributesW(path) == INVALID_FILE_ATTRIBUTES) return 109;
        search = FindFirstFileW(path, &found);
        if (search == INVALID_HANDLE_VALUE || memcmp(found.cFileName, path+8, 9*sizeof(WCHAR))) return 110;
        FindClose(search);
        if (!GetCurrentDirectoryA(sizeof(saved_cwd), saved_cwd) ||
            !CreateDirectoryA("C:\\APPS\\caf\xe9", NULL) ||
            !SetCurrentDirectoryW(L"C:\\APPS\\caf\x00e9") ||
            GetCurrentDirectoryA(sizeof(converted), converted) != 12 ||
            strcmp(converted, "C:\\APPS\\caf\xe9") || !SetCurrentDirectoryA(saved_cwd)) return 111;
        file = CreateFileA("C:\\APPS\\caf\xe9\\x.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
        if (file == INVALID_HANDLE_VALUE || !CloseHandle(file)) return 112;
        SetFileApisToOEM();
        if (AreFileApisANSI() || GetFileAttributesA("C:\\APPS\\caf\x82\\x.txt") == INVALID_FILE_ATTRIBUTES) return 113;
        SetFileApisToANSI();
        if (!AreFileApisANSI()) return 114;
        if (!SetConsoleOutputCP(1251) || GetConsoleOutputCP() != 1251 ||
            !SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), origin) ||
            !WriteConsoleA(GetStdHandle(STD_OUTPUT_HANDLE), "\xc6", 1, &n, NULL) || n != 1 ||
            !ReadConsoleOutputW(GetStdHandle(STD_OUTPUT_HANDLE), &cell, one, origin, &rect) ||
            cell.Char.UnicodeChar != 0x0416) return 115;
        if (!SetConsoleOutputCP(GetOEMCP())) return 116;
    }
    {
        const DWORD kinds[] = {LOCALE_IDATE, LOCALE_ITIME, LOCALE_SDATE, LOCALE_STIME,
            LOCALE_STHOUSAND, LOCALE_SDECIMAL, LOCALE_ICURRDIGITS, LOCALE_SCURRENCY};
        const char *values[] = {"0", "0", "/", ":", ",", ".", "2", "$"};
        DWORD number;
        WCHAR wide[8];
        for (i = 0; i < sizeof(kinds) / sizeof(kinds[0]); ++i) {
            memset(env, 0xcc, sizeof(env));
            if (GetLocaleInfoA(LOCALE_USER_DEFAULT, kinds[i], env, sizeof(env)) != 2 ||
                strcmp(env, values[i]) || (unsigned char)env[2] != 0xcc) return 85;
        }
        if (GetLocaleInfoA(LOCALE_USER_DEFAULT, LOCALE_SSHORTDATE, NULL, 0) != 9) return 86;
        env[0] = '!';
        if (GetLocaleInfoA(LOCALE_USER_DEFAULT, LOCALE_SDATE, env, 1) != 0 ||
            GetLastError() != ERROR_INSUFFICIENT_BUFFER || env[0] != '!') return 87;
        if (GetLocaleInfoW(LOCALE_USER_DEFAULT, LOCALE_STIME, wide, 8) != 2 ||
            wide[0] != ':' || wide[1] != 0) return 88;
        if (GetLocaleInfoA(LOCALE_USER_DEFAULT, LOCALE_ILANGUAGE | LOCALE_RETURN_NUMBER,
                (char *)&number, sizeof(number)) != 4 || number != 0x0409) return 89;
        if (GetLocaleInfoW(LOCALE_USER_DEFAULT, LOCALE_ICURRDIGITS | LOCALE_RETURN_NUMBER,
                (WCHAR *)&number, 2) != 2 || number != 2) return 90;
    }
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
