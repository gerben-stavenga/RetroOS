/* Shared Wine Win32 wave path, also used by MMSYSTEM's Win16 thunks. */
#include <stdarg.h>
#include <windef.h>
#include <winbase.h>
#include <mmsystem.h>
__declspec(dllimport) BOOL WINAPI RetroWriteFile(DWORD,const void *,DWORD,DWORD *,void *);
static volatile unsigned done,opened,closed;
static unsigned errors;
static BYTE samples[2205];
static void check_at(BOOL ok,unsigned line) {
    if(!ok) {
        DWORD written;char text[]="WAVE CHECK 000\n";errors++;
        text[11]='0'+line/100%10;text[12]='0'+line/10%10;text[13]='0'+line%10;
        RetroWriteFile(1,text,sizeof(text)-1,&written,0);
    }
}
#define check(ok) check_at((ok),__LINE__)
static void CALLBACK callback(HWAVEOUT h,UINT msg,DWORD_PTR user,DWORD_PTR a,DWORD_PTR b)
{
    if(msg==WOM_DONE)done++;if(msg==WOM_OPEN)opened++;if(msg==WOM_CLOSE)closed++;
}
void start(void)
{
    HWAVEOUT wave=NULL;WAVEHDR header={0};WAVEFORMATEX format={WAVE_FORMAT_PCM,1,22050,22050,1,8,0};
    MMTIME position={0};DWORD written;
    check(waveOutGetNumDevs()>0);
    check(waveOutOpen(&wave,WAVE_MAPPER,&format,(DWORD_PTR)callback,0,CALLBACK_FUNCTION)==0);
    if(wave) {
        check(opened==1);
        for(unsigned i=0;i<sizeof(samples);i++) samples[i]=(i/25)&1?176:80;
        header.lpData=(char *)samples;header.dwBufferLength=sizeof(samples);
        check(waveOutPrepareHeader(wave,&header,sizeof(header))==0);
        check(waveOutPause(wave)==0);
        check(waveOutWrite(wave,&header,sizeof(header))==0);
        Sleep(30);check(done==0 && (header.dwFlags&WHDR_INQUEUE));
        check(waveOutRestart(wave)==0);
        for(unsigned i=0;i<200 && !done;i++) Sleep(5);
        check(done==1 && (header.dwFlags&WHDR_DONE) && !(header.dwFlags&WHDR_INQUEUE));
        position.wType=TIME_BYTES;
        check(waveOutGetPosition(wave,&position,sizeof(position))==0);
        check(position.wType==TIME_BYTES && position.u.cb==sizeof(samples));
        check(waveOutUnprepareHeader(wave,&header,sizeof(header))==0);
        check(waveOutClose(wave)==0);check(closed==1);
    }
    if(errors) RetroWriteFile(1,"WAVE FAIL\n",10,&written,0);
    else RetroWriteFile(1,"WAVE PASS\n",10,&written,0);
    ExitProcess(errors?1:0);
}
