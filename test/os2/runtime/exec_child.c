#define INCL_DOS
#include <os2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    TIB *tib; PIB *pib;
    char path[260];
    const char *value = getenv("RETRO_EXEC_PROBE");
    if (argc != 2 || strcmp(argv[1], "argument") || !value || strcmp(value, "value")) return 91;
    if (DosGetInfoBlocks(&tib, &pib) != 0 ||
        DosQueryModuleName(pib->pib_hmte, sizeof(path), path) != 0 ||
        strcmp(path, "C:\\OS2\\APPS\\EXECCHILD.EXE")) return 92;
    puts("OS2EXEC CHILD PASS");
    return 37;
}
