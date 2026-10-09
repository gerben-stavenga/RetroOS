#define INCL_DOS
#include <os2.h>
#include <stdio.h>
#include <string.h>
#define CHECK(test) do { if (!(test)) { printf("OS2UCONV FAIL %u\n", __LINE__); return 1; } } while (0)
int main(void) {
    char error[260];
    HMODULE module;
    PFN procedure;
    {
        typedef ULONG (APIENTRY *CREATE)(USHORT *, PVOID *);
        typedef ULONG (APIENTRY *MAPCP)(ULONG, USHORT *, ULONG);
        typedef ULONG (APIENTRY *CONVERT)(PVOID, PVOID *, ULONG *, PVOID *, ULONG *, ULONG *);
        typedef ULONG (APIENTRY *FREECONV)(PVOID);
        CREATE create; MAPCP mapcp; CONVERT to_ucs, from_ucs; FREECONV freeconv;
        USHORT name[16], unicode[256];
        unsigned char source[256], destination[256];
        PVOID object, in, out;
        ULONG left, room, substitutions, i;
        CHECK(DosLoadModule(error, sizeof(error), "UCONV", &module) == 0);
        CHECK(DosQueryProcAddr(module, 1, NULL, &procedure) == 0); create = (CREATE)procedure;
        CHECK(DosQueryProcAddr(module, 2, NULL, &procedure) == 0); to_ucs = (CONVERT)procedure;
        CHECK(DosQueryProcAddr(module, 3, NULL, &procedure) == 0); from_ucs = (CONVERT)procedure;
        CHECK(DosQueryProcAddr(module, 4, NULL, &procedure) == 0); freeconv = (FREECONV)procedure;
        CHECK(DosQueryProcAddr(module, 10, NULL, &procedure) == 0); mapcp = (MAPCP)procedure;
        CHECK(mapcp(866, name, 2) == 0x20412);
        CHECK(mapcp(866, name, 16) == 0 && name[0] == 'I');
        CHECK(create(name, &object) == 0);
        for (i = 0; i < 256; ++i) source[i] = (unsigned char)i;
        in = source; out = unicode; left = 256; room = 128;
        CHECK(to_ucs(object, &in, &left, &out, &room, &substitutions) == 0x20412);
        CHECK(left == 128 && room == 0 && in == source + 128 && out == unicode + 128);
        room = 128;
        CHECK(to_ucs(object, &in, &left, &out, &room, &substitutions) == 0 && left == 0);
        CHECK(unicode[0] == 0 && unicode[128] == 0x410);
        in = unicode; out = destination; left = 256; room = 256;
        CHECK(from_ucs(object, &in, &left, &out, &room, &substitutions) == 0);
        CHECK(left == 0 && substitutions == 0 && memcmp(source, destination, 256) == 0);
        CHECK(freeconv(object) == 0 && freeconv(object) == 0x2040f);
        {
            char attribute[] = "@subchar=\\x3F";
            for (i = 0; i < sizeof(attribute); ++i) name[i] = attribute[i];
        }
        CHECK(create(name, &object) == 0);
        unicode[0] = 0x410;
        in = unicode; out = destination; left = 1; room = 1;
        CHECK(from_ucs(object, &in, &left, &out, &room, &substitutions) == 0);
        CHECK(destination[0] == '?' && substitutions == 1);
        CHECK(freeconv(object) == 0);
        CHECK(mapcp(1208, name, 16) == 0 && create(name, &object) == 0);
        source[0] = 0xd0; source[1] = 0x90;
        in = source; out = unicode; left = 1; room = 1;
        CHECK(to_ucs(object, &in, &left, &out, &room, &substitutions) == 0x20402);
        CHECK(left == 1 && in == source && room == 1);
        left = 2;
        CHECK(to_ucs(object, &in, &left, &out, &room, &substitutions) == 0 && unicode[0] == 0x410);
        in = unicode; out = destination; left = 1; room = 1;
        CHECK(from_ucs(object, &in, &left, &out, &room, &substitutions) == 0x20412);
        CHECK(left == 1 && room == 1 && out == destination);
        room = 2;
        CHECK(from_ucs(object, &in, &left, &out, &room, &substitutions) == 0);
        CHECK(destination[0] == 0xd0 && destination[1] == 0x90);
        CHECK(freeconv(object) == 0);
        CHECK(mapcp(12345, name, 16) == 0x20414);
        CHECK(DosFreeModule(module) == 0);
    }
    {
        typedef ULONG (APIENTRY *QUERYINT)(ULONG, const char *, const char *, ULONG);
        typedef ULONG (APIENTRY *QUERYSTRING)(ULONG, const char *, const char *, const char *, PVOID, ULONG);
        typedef ULONG (APIENTRY *ALARM)(ULONG, ULONG);
        QUERYINT queryint; QUERYSTRING querystring; ALARM alarm;
        char buffer[8];
        CHECK(DosLoadModule(error, sizeof(error), "PMSHAPI", &module) == 0);
        CHECK(DosQueryProcAddr(module, 114, NULL, &procedure) == 0); queryint = (QUERYINT)procedure;
        CHECK(DosQueryProcAddr(module, 115, NULL, &procedure) == 0); querystring = (QUERYSTRING)procedure;
        CHECK(queryint(0xffffffffUL, "missing", "key", 0xfffffffeUL) == 0xfffffffeUL);
        memset(buffer, 0xcc, sizeof(buffer));
        CHECK(querystring(0xffffffffUL, "missing", "key", "hello", buffer, 4) == 4);
        CHECK(strcmp(buffer, "hel") == 0 && (unsigned char)buffer[4] == 0xcc);
        CHECK(querystring(0xffffffffUL, "missing", "key", NULL, buffer, 8) == 1 && buffer[0] == 0);
        CHECK(querystring(0xffffffffUL, "missing", "key", "hello", buffer, 0) == 0);
        CHECK(querystring(0xffffffffUL, NULL, NULL, "hello", buffer, 8) == 0 && buffer[0] == 0 && buffer[1] == 0);
        CHECK(DosFreeModule(module) == 0);
        CHECK(DosLoadModule(error, sizeof(error), "PMWIN", &module) == 0);
        CHECK(DosQueryProcAddr(module, 701, NULL, &procedure) == 0); alarm = (ALARM)procedure;
        CHECK(alarm(1, 1) == 0);
        CHECK(DosFreeModule(module) == 0);
    }
    {
        DATETIME now;
        ULONG result = DosGetDateTime(&now);
        CHECK(result == 0 || result == 13); /* Hosted backend has no RTC. */
        if (result == 0) {
            CHECK(now.year >= 2000 && now.month >= 1 && now.month <= 12);
            CHECK(now.day >= 1 && now.day <= 31 && now.hours < 24 && now.minutes < 60 && now.seconds < 60);
            CHECK(now.weekday < 7 && now.timezone == -1);
            printf("OS2CLOCK %u-%02u-%02u %02u:%02u:%02u weekday=%u\n",
                now.year, now.month, now.day, now.hours, now.minutes, now.seconds, now.weekday);
        }
    }
    puts("OS2UCONV PASS");
    return 0;
}
