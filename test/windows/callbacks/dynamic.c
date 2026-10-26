/* USER32 is first loaded at runtime, so its private and ordinary gates must
 * be registered by LoadLibrary as well as by the executable's import loader. */
#include <windows.h>
#include <stdio.h>

static unsigned created;
static LRESULT CALLBACK wndproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    (void)hwnd; (void)wp; (void)lp;
    if (msg == WM_NCCREATE) return 1;
    if (msg == WM_CREATE) ++created;
    return 0;
}

int main(void)
{
    static const WCHAR name[] = {'D','y','n','a','m','i','c',0};
    WNDCLASSW wc = {0};
    HMODULE user = LoadLibraryA("USER32.DLL");
    ATOM (WINAPI *reg)(const WNDCLASSW *);
    HWND (WINAPI *create)(DWORD,LPCWSTR,LPCWSTR,DWORD,int,int,int,int,HWND,HMENU,HINSTANCE,LPVOID);
    if (!user) return 1;
    reg = (void *)GetProcAddress(user, "RegisterClassW");
    create = (void *)GetProcAddress(user, "CreateWindowExW");
    if (!reg || !create) return 2;
    wc.lpfnWndProc = wndproc;
    wc.lpszClassName = name;
    if (!reg(&wc)) return 3;
    if (!create(0, name, name, WS_POPUP | WS_VISIBLE, 1, 2, 32, 32, 0, 0, 0, 0)) return 4;
    if (created != 1) return 5;
    puts("WINCALLBACK PASS");
    return 0;
}
