#include <windows.h>
#include <stdio.h>
int main(void) {
    INPUT_RECORD key;
    WCHAR text[128];
    unsigned char bytes[256];
    DWORD count;
    unsigned int n = 0, i;
    printf("KEYBOARD READY\n"); fflush(stdout);
    while (n < 128) {
        if (!ReadConsoleInputW(GetStdHandle(STD_INPUT_HANDLE),&key,1,&count)) return 1;
        if (!count || key.EventType != KEY_EVENT || !key.Event.KeyEvent.bKeyDown || !key.Event.KeyEvent.uChar.UnicodeChar) continue;
        text[n++] = key.Event.KeyEvent.uChar.UnicodeChar;
        if (text[n-1] == '\r') break;
    }
    printf("KEYBOARD W ");
    for (i=0;i<n;++i) printf("%04X ",text[i]);
    printf("\n");
    if (!SetConsoleCP(65001)) return 2;
    printf("KEYBOARD UTF8 READY\n"); fflush(stdout);
    n = 0;
    while (n < sizeof(bytes)) {
        if (!ReadConsoleInputA(GetStdHandle(STD_INPUT_HANDLE),&key,1,&count)) return 3;
        if (!count || key.EventType != KEY_EVENT || !key.Event.KeyEvent.bKeyDown || !key.Event.KeyEvent.uChar.AsciiChar) continue;
        bytes[n++] = (unsigned char)key.Event.KeyEvent.uChar.AsciiChar;
        if (bytes[n-1] == '\r') break;
    }
    printf("KEYBOARD A ");
    for (i=0;i<n;++i) printf("%02X ",bytes[i]);
    printf("\n"); return 0;
}
