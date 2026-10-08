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
    {
        const char *image = pib->pib_pchcmd - 2;
        while (*image) --image;
        if (strcmp(image + 1, path) || strcmp(pib->pib_pchcmd, path) ||
            strcmp(pib->pib_pchcmd + strlen(pib->pib_pchcmd) + 1, "argument")) return 93;
    }
    puts("OS2EXEC CHILD PASS");
    return 37;
}
