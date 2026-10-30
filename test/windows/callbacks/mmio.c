#include <windows.h>
#include <stdio.h>
#include <string.h>
typedef struct {DWORD id,size,type,offset,flags;} Chunk;
typedef UINT (WINAPI *OpenFn)(char*,DWORD*,DWORD);
typedef UINT (WINAPI *CloseFn)(UINT,UINT);
typedef LONG (WINAPI *ReadFn)(UINT,void*,LONG);
typedef LONG (WINAPI *SeekFn)(UINT,LONG,UINT);
typedef UINT (WINAPI *InfoFn)(UINT,DWORD*,UINT);
typedef UINT (WINAPI *DescendFn)(UINT,Chunk*,Chunk*,UINT);
typedef UINT (WINAPI *ChunkFn)(UINT,Chunk*,UINT);
typedef DWORD (WINAPI *FourFn)(char*,UINT);
static unsigned errors;
#define CHECK(x) do {if(!(x)){++errors;printf("mmio check failed line %u\n",__LINE__);}}while(0)
#define FOUR(a,b,c,d) ((DWORD)(a)|((DWORD)(b)<<8)|((DWORD)(c)<<16)|((DWORD)(d)<<24))
int main(void)
{
    HMODULE mm=LoadLibraryA("WINMM.DLL");
    OpenFn open=(OpenFn)GetProcAddress(mm,"mmioOpenA");
    CloseFn close=(CloseFn)GetProcAddress(mm,"mmioClose");
    ReadFn read=(ReadFn)GetProcAddress(mm,"mmioRead"),write=(ReadFn)GetProcAddress(mm,"mmioWrite");
    SeekFn seek=(SeekFn)GetProcAddress(mm,"mmioSeek");
    InfoFn info=(InfoFn)GetProcAddress(mm,"mmioGetInfo"),set=(InfoFn)GetProcAddress(mm,"mmioSetInfo"),advance=(InfoFn)GetProcAddress(mm,"mmioAdvance");
    DescendFn descend=(DescendFn)GetProcAddress(mm,"mmioDescend");
    ChunkFn ascend=(ChunkFn)GetProcAddress(mm,"mmioAscend"),create=(ChunkFn)GetProcAddress(mm,"mmioCreateChunk");
    FourFn four=(FourFn)GetProcAddress(mm,"mmioStringToFOURCCA");
    UINT h,i;DWORD state[18]={0},saved[18],done;HANDLE raw;
    Chunk root={0},chunk={0},sentinel;
    unsigned char buffer[32],bytes[80];
    CHECK(mm && open && close && read && write && seek && info && set && advance && descend && ascend && create && four);
    if(!mm || !open || !close || !read || !write || !seek || !info || !set || !advance || !descend || !ascend || !create || !four)return 1;
    CHECK(four("wav",0x10)==FOUR('W','A','V',' '));
    state[5]=7; /* force header/data reads across buffer boundaries */
    h=open("MMIO.RIF",state,0x11002);CHECK(h!=0);
    root.type=FOUR('T','E','S','T');CHECK(create(h,&root,0x20)==0);
    chunk.id=FOUR('J','U','N','K');CHECK(create(h,&chunk,0)==0);CHECK(write(h,"abc",3)==3);CHECK(ascend(h,&chunk,0)==0 && chunk.size==3);
    chunk.id=FOUR('d','a','t','a');CHECK(create(h,&chunk,0)==0);CHECK(write(h,"hello",5)==5);CHECK(ascend(h,&chunk,0)==0 && chunk.size==5);
    CHECK(ascend(h,&root,0)==0 && root.size==30);CHECK(close(h,0)==0);CHECK(close(h,0)==5);
    memset(state,0,sizeof(state));state[5]=7;h=open("MMIO.RIF",state,0x10000);CHECK(h!=0);
    CHECK(info(h,state,0)==0 && state[5]==7 && state[6]!=0);
    CHECK(advance(h,state,0)==0 && state[8]-state[6]==7);
    CHECK(memcmp((void*)state[6],"RIFF",4)==0);
    state[7]+=3;CHECK(set(h,state,0)==0 && seek(h,0,1)==3);
    memcpy(saved,state,sizeof(state));state[7]=state[6]+state[5]+1;CHECK(set(h,state,0)==11);memcpy(state,saved,sizeof(state));
    CHECK(seek(h,0,0)==0);memset(&root,0,sizeof(root));root.type=FOUR('T','E','S','T');
    CHECK(descend(h,&root,0,0x20)==0 && root.size==30 && seek(h,0,1)==12);
    memset(&chunk,0,sizeof(chunk));chunk.id=FOUR('d','a','t','a');CHECK(descend(h,&chunk,&root,0x10)==0 && chunk.size==5 && chunk.offset==32);
    CHECK(read(h,buffer,5)==5 && memcmp(buffer,"hello",5)==0);
    CHECK(ascend(h,&chunk,0)==0 && seek(h,0,1)==38);
    CHECK(descend(h,&chunk,&root,0)==265);CHECK(read(h,buffer,1)==0);
    CHECK(seek(h,-1,0)==-1);CHECK(close(h,0)==0);CHECK(read(h,buffer,1)==-1);
    raw=CreateFileA("MMIO.RIF",GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,0,0);
    CHECK(ReadFile(raw,bytes,sizeof(bytes),&done,0) && done==38);CloseHandle(raw);
    CHECK(bytes[23]==0 && bytes[37]==0); /* odd-sized chunk padding */
    memset(state,0,sizeof(state));state[1]=FOUR('M','E','M',' ');state[5]=38;state[6]=(DWORD)bytes;
    h=open(0,state,2);CHECK(h!=0);CHECK(read(h,buffer,4)==4 && memcmp(buffer,"RIFF",4)==0);
    CHECK(seek(h,0,0)==0);root.type=FOUR('T','E','S','T');CHECK(descend(h,&root,0,0x20)==0);
    CHECK(advance(h,0,0)==261);CHECK(seek(h,39,0)==-1);CHECK(close(h,0)==0);
    /* Parent bounds and overflowing/truncated lengths must not be traversed. */
    bytes[4]=0xff;bytes[5]=bytes[6]=bytes[7]=0xff;
    memset(state,0,sizeof(state));state[1]=FOUR('M','E','M',' ');state[5]=38;state[6]=(DWORD)bytes;
    h=open(0,state,0);memset(&chunk,0x55,sizeof(chunk));sentinel=chunk;
    CHECK(descend(h,&chunk,0,0)==265 && memcmp(&chunk,&sentinel,sizeof(chunk))==0);CHECK(close(h,0)==0);
    memset(state,0,sizeof(state));h=open("DOESNOTEXIST.RIF",state,0x10000);CHECK(!h && state[3]==257);
    /* Unsupported custom procedures fail rather than being ignored. */
    memset(state,0,sizeof(state));state[2]=1;CHECK(!open("MMIO.RIF",state,0) && state[3]==259);
    for(i=0;i<100;++i){h=open("MMIO.RIF",0,0);CHECK(h!=0);CHECK(close(h,0)==0);}
    DeleteFileA("MMIO.RIF");
    printf("WINCALLBACK %s mmio (%u errors)\n",errors?"FAIL":"PASS",errors);return errors?1:0;
}
