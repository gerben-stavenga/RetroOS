#include <stdio.h>
#include <string.h>

static const char payload[] = "Open Watcom Win32 file I/O works\n";

int main(void)
{
    char buffer[sizeof(payload)];
    FILE *file = fopen("C:\\WINDOWS\\APPS\\WATCOM.TXT", "w+b");
    if (file == NULL) return 10;
    if (fwrite(payload, 1, sizeof(payload) - 1, file) != sizeof(payload) - 1) return 11;
    if (fseek(file, 0, SEEK_SET) != 0) return 12;
    memset(buffer, 0, sizeof(buffer));
    if (fread(buffer, 1, sizeof(payload) - 1, file) != sizeof(payload) - 1) return 13;
    if (fclose(file) != 0) return 14;
    if (memcmp(buffer, payload, sizeof(payload) - 1) != 0) return 15;
    printf("%s", buffer);
    return 0;
}
