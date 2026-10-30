#include <windows.h>
#include <stdio.h>
#include <string.h>
typedef DWORD (WINAPI *CaseBuffer)(void*,DWORD);
static unsigned errors;
#define CHECK(x) do {if(!(x)){++errors;printf("text check failed line %u\n",__LINE__);}}while(0)
int main(void)
{
    HMODULE user=LoadLibraryA("USER32.DLL");
    CaseBuffer lower=(CaseBuffer)GetProcAddress(user,"CharLowerBuffA"),upper=(CaseBuffer)GetProcAddress(user,"CharUpperBuffA");
    CaseBuffer lower_w=(CaseBuffer)GetProcAddress(user,"CharLowerBuffW"),upper_w=(CaseBuffer)GetProcAddress(user,"CharUpperBuffW");
    char ansi[]={'A',0,'Z',(char)0xc9,'!','X'};
    WCHAR wide[]={'A',0,0x00c9,0x03a9,0xd800,'!','X'};
    CHECK(lower && upper && lower_w && upper_w);
    if(!lower || !upper || !lower_w || !upper_w)return 1;
    CHECK(GetACP()==1252);
    CHECK(lower(ansi,5)==5 && !memcmp(ansi,"a\0z\xe9!X",6));
    CHECK(upper(ansi,5)==5 && !memcmp(ansi,"A\0Z\xc9!X",6));
    CHECK(lower_w(wide,6)==6 && wide[0]=='a' && wide[1]==0 && wide[2]==0x00e9 && wide[3]==0x03c9 && wide[4]==0xd800 && wide[5]=='!' && wide[6]=='X');
    CHECK(upper_w(wide,6)==6 && wide[0]=='A' && wide[2]==0x00c9 && wide[3]==0x03a9 && wide[4]==0xd800 && wide[6]=='X');
    CHECK(lower(ansi,0)==0 && ansi[0]=='A');
    CHECK(lower_w(wide,0)==0 && wide[0]=='A');
    CHECK(lower(0,3)==0 && upper_w(0,3)==0);
    printf("WINCALLBACK %s text (%u errors)\n",errors?"FAIL":"PASS",errors);
    return errors?1:0;
}
