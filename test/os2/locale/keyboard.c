#define INCL_KBD
#include <os2.h>
#include <stdio.h>
int main(void) {
    KBDKEYINFO key;
    unsigned char text[128];
    unsigned int n = 0, i;
    printf("KEYBOARD READY\n"); fflush(stdout);
    while (n < sizeof(text)) {
        if (KbdCharIn(&key,IO_WAIT,0)) return 1;
        if (!key.chChar) continue;
        text[n++] = key.chChar;
        if (key.chChar == '\r') break;
    }
    printf("KEYBOARD OS2 ");
    for (i=0;i<n;++i) printf("%02X ",text[i]);
    printf("\n"); return 0;
}
