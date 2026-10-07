#include <windows.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    char path[260];
    HMODULE local;
    DWORD (WINAPI *probe)(void);
    if (!GetModuleFileNameA(NULL, path, sizeof(path)) ||
        strcmp(path, "C:\\APPS\\WINCHILD.EXE")) return 91;
    if (!GetCurrentDirectoryA(sizeof(path), path) || strcmp(path, "C:\\WORK")) return 92;
    local = LoadLibraryA("LOCAL.DLL");
    probe = (DWORD (WINAPI *)(void))GetProcAddress(local, "ProbeValue");
    if (!probe || probe() != 1) return 93;
    FreeLibrary(local);
    puts("WINCHILD PASS");
    return 0;
}
