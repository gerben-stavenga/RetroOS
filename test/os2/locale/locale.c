#define INCL_DOS
#include <os2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(c) do { if (!(c)) { printf("LOCALE OS2 FAIL line %d\n", __LINE__); return 1; } } while (0)

int main(void)
{
    char tag[32];
    FILE *expected;
    TIB *tib; PIB *pib;
    const char *entry;
    COUNTRYCODE query = {0, 0};
    COUNTRYINFO info;
    ULONG country = 1, oem = 437, order = 0, cp, size;
    unsigned long requested;
    char letter = 'a';
    const char *decimal = ".", *currency = "$";
    CHECK(DosGetInfoBlocks(&tib, &pib) == 0);
    for (entry = pib->pib_pchenv; *entry; entry += strlen(entry) + 1) {
        CHECK(strnicmp(entry,"LOCALE=",7) && strnicmp(entry,"KEYBOARD=",9) && strnicmp(entry,"CODEPAGE=",9));
    }
    expected = fopen("EXPECT.TXT", "r");
    CHECK(expected && fscanf(expected, "%31s %lu", tag, &requested) == 2);
    fclose(expected);
    if (!stricmp(tag, "ru-RU")) {
        country = 7; oem = 866; order = 1; decimal = ",";
        currency = "\xe0\xe3\xa1.";
    } else if (!stricmp(tag, "pl-PL")) {
        country = 48; oem = 852; order = 1; decimal = ",";
        currency = "z\x88";
    } else if (!stricmp(tag, "de-DE") || !stricmp(tag, "it-IT") || !stricmp(tag, "nl-NL")) {
        country = !stricmp(tag, "de-DE") ? 49 : !stricmp(tag, "it-IT") ? 39 : 31;
        oem = 850; order = 1; decimal = ","; currency = "EUR";
    }
    oem = requested;
    CHECK(DosQueryCp(sizeof(cp), &cp, &size) == 0 && size == 4 && cp == oem);
    CHECK(DosQueryCtryInfo(sizeof(info), &query, &info, &size) == 0 && size == 44);
    CHECK(info.country == country && info.codepage == oem && info.fsDateFmt == order);
    CHECK(!strcmp(info.szDecimal, decimal));
    if (oem == (country == 7 ? 866 : country == 48 ? 852 : country == 1 ? 437 : 850)) CHECK(!strcmp(info.szCurrency, currency));
    CHECK(info.cDecimalPlace == 2 && info.fsTimeFmt == (country != 1));
    if (oem == 866) letter = (char)0xa6; /* Cyrillic small zhe */
    else if (oem == 852) letter = (char)0x88; /* Polish small l with stroke */
    CHECK(DosMapCase(1, &query, &letter) == 0);
    CHECK((unsigned char)letter == (oem == 866 ? 0x86 : oem == 852 ? 0x9d : 'A'));
    query.country = 1;
    CHECK(DosQueryCtryInfo(sizeof(info), &query, &info, &size) == 0 && info.country == 1 && info.fsDateFmt == 0);
    query.country = 999;
    CHECK(DosQueryCtryInfo(sizeof(info), &query, &info, &size) == 398);
    printf("LOCALE OS2 PASS\n");
    return 0;
}
