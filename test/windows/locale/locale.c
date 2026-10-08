#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(c) do { if (!(c)) { printf("LOCALE WINDOWS FAIL line %d\n", __LINE__); return 1; } } while (0)

int main(void)
{
    char tag[32], value[128], converted[128];
    FILE *expected;
    WCHAR wide[128], sample;
    DWORD lcid = 0x409, ansi = 1252, oem = 437, country = 1, number;
    const char *expected_tag = "en-US", *decimal = ".";
    int count, i;
    unsigned long requested;
    unsigned char byte = 0xe9;
    sample = 0x00e9;
    CHECK(GetEnvironmentVariableA("LOCALE", tag, sizeof(tag)) == 0);
    CHECK(GetEnvironmentVariableA("KEYBOARD", tag, sizeof(tag)) == 0);
    CHECK(GetEnvironmentVariableA("CODEPAGE", tag, sizeof(tag)) == 0);
    expected = fopen("EXPECT.TXT", "r");
    CHECK(expected && fscanf(expected, "%31s %lu", tag, &requested) == 2);
    fclose(expected);
    {
        if (!stricmp(tag, "ru-RU")) {
            lcid = 0x419; ansi = 1251; oem = 866; country = 7;
            expected_tag = "ru-RU"; decimal = ","; byte = 0xc6; sample = 0x0416;
        } else if (!stricmp(tag, "pl-PL")) {
            lcid = 0x415; ansi = 1250; oem = 852; country = 48;
            expected_tag = "pl-PL"; decimal = ","; byte = 0xa3; sample = 0x0141;
        } else if (!stricmp(tag, "de-DE")) {
            lcid = 0x407; oem = 850; country = 49; expected_tag = "de-DE"; decimal = ",";
        } else if (!stricmp(tag, "it-IT")) {
            lcid = 0x410; oem = 850; country = 39; expected_tag = "it-IT"; decimal = ",";
        } else if (!stricmp(tag, "nl-NL")) {
            lcid = 0x413; oem = 850; country = 31; expected_tag = "nl-NL"; decimal = ",";
        }
    }
    oem = requested;
    CHECK(GetACP() == ansi && GetOEMCP() == oem);
    CHECK(GetUserDefaultLCID() == lcid && GetSystemDefaultLCID() == lcid);
    CHECK(GetUserDefaultLangID() == lcid && GetSystemDefaultLangID() == lcid);
    CHECK(GetThreadLocale() == lcid);
    CHECK(GetLocaleInfoA(LOCALE_USER_DEFAULT, LOCALE_ICOUNTRY | LOCALE_RETURN_NUMBER,
        (char *)&number, 4) == 4 && number == country);
    CHECK(GetLocaleInfoW(LOCALE_SYSTEM_DEFAULT, LOCALE_ILANGUAGE | LOCALE_RETURN_NUMBER,
        (WCHAR *)&number, 2) == 2 && number == lcid);
    CHECK(GetLocaleInfoA(LOCALE_USER_DEFAULT, 0x5c, value, sizeof(value)) && !strcmp(value, expected_tag));
    CHECK(GetLocaleInfoA(LOCALE_USER_DEFAULT, LOCALE_SDECIMAL, value, sizeof(value)) == 2 && !strcmp(value, decimal));
    CHECK(MultiByteToWideChar(0, 0, (char *)&byte, 1, wide, 128) == 1 && wide[0] == sample);
    CHECK(GetLocaleInfoA(LOCALE_USER_DEFAULT, LOCALE_IDEFAULTANSICODEPAGE | LOCALE_RETURN_NUMBER,
        (char *)&number, 4) == 4 && number == ansi);
    CHECK(GetLocaleInfoA(LOCALE_USER_DEFAULT, LOCALE_IDEFAULTCODEPAGE | LOCALE_RETURN_NUMBER,
        (char *)&number, 4) == 4 && number == oem);
    count = GetLocaleInfoW(LOCALE_USER_DEFAULT, LOCALE_SLANGUAGE, NULL, 0);
    CHECK(count > 1 && count < 128);
    for (i = 0; i < 128; ++i) wide[i] = 0xeeee;
    CHECK(GetLocaleInfoW(LOCALE_USER_DEFAULT, LOCALE_SLANGUAGE, wide, count - 1) == 0 &&
        GetLastError() == ERROR_INSUFFICIENT_BUFFER && wide[0] == 0xeeee);
    CHECK(GetLocaleInfoW(LOCALE_USER_DEFAULT, LOCALE_SLANGUAGE, wide, count) == count &&
        wide[count - 1] == 0 && wide[count] == 0xeeee);
    CHECK(GetLocaleInfoA(LOCALE_USER_DEFAULT, LOCALE_SLANGUAGE, value, sizeof(value)) == count);
    CHECK(WideCharToMultiByte(ansi, 0, wide, -1, converted, sizeof(converted), NULL, NULL) == count &&
        !strcmp(value, converted));
    CHECK(GetLocaleInfoA(0x409, LOCALE_ILANGUAGE | LOCALE_RETURN_NUMBER, (char *)&number, 4) == 4 && number == 0x409);
    CHECK(GetLocaleInfoA(0x419, LOCALE_SLANGUAGE, value, sizeof(value)) && (unsigned char)value[0] == 0xd0);
    CHECK(GetLocaleInfoA(0x419, LOCALE_SLANGUAGE | 0x40000000, converted, sizeof(converted)));
    CHECK(GetLocaleInfoW(0x419, LOCALE_SLANGUAGE, wide, 128));
    CHECK(WideCharToMultiByte(ansi, 0, wide, -1, value, sizeof(value), NULL, NULL) && !strcmp(value, converted));
    printf("LOCALE WINDOWS PASS\n");
    return 0;
}
