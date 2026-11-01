/* RetroOS PCM driver for Wine's Win16 and Win32 wave-output wrappers. */
#include "mmsystem.h"
#include "mmddk.h"
extern NTSTATUS WINAPI RetroNtClose(HANDLE);
static DWORD wave_volume=0xffffffff;
extern NTSTATUS WINAPI RetroPcm(ULONG,ULONG,const void *,ULONG,ULONG,void *);
extern NTSTATUS WINAPI RetroNtDelayExecution(BOOLEAN,const LARGE_INTEGER *);
static BOOL (WINAPI *wave_callback)(DWORD_PTR,DWORD,HDRVR,DWORD,DWORD_PTR,DWORD_PTR,DWORD_PTR);
void WINAPI RetroWaveInit(void *callback) { wave_callback=callback; }
struct wave_stream {
    RTL_SRWLOCK lock;
    ULONG native;
    WAVEOPENDESC desc;
    DWORD flags;
    WAVEFORMATEX format;
    WAVEHDR *head,*tail,*sending;
    DWORD offset;
    ULONGLONG completed;
    BOOL closing;
};
static void wave_notify(struct wave_stream *s,UINT message,WAVEHDR *header)
{
    wave_callback(s->desc.dwCallback,HIWORD(s->flags),(HDRVR)s->desc.hWave,message,
                  s->desc.dwInstance,(DWORD_PTR)header,0);
}
static void wave_finish(struct wave_stream *s,WAVEHDR *list)
{
    while(list) {
        WAVEHDR *next=list->lpNext;
        list->dwFlags=(list->dwFlags&~WHDR_INQUEUE)|WHDR_DONE;
        wave_notify(s,WOM_DONE,list);list=next;
    }
}
static DWORD WINAPI wave_thread(void *parameter)
{
    struct wave_stream *s=parameter;
    LARGE_INTEGER delay;delay.QuadPart=-50000; /* 5 ms; completion uses the DAC cursor */
    for(;;) {
        WAVEHDR *done=NULL,**end=&done;
        ULONGLONG played=0;
        RtlAcquireSRWLockExclusive(&s->lock);
        if(s->closing) {RtlReleaseSRWLockExclusive(&s->lock);break;}
        RetroPcm(2,s->native,NULL,0,0,&played);
        while(s->head && s->head!=s->sending && played>=s->completed+s->head->dwBufferLength) {
            WAVEHDR *h=s->head;s->completed+=h->dwBufferLength;s->head=h->lpNext;
            h->lpNext=NULL;*end=h;end=&h->lpNext;
        }
        if(!s->head) s->tail=NULL;
        while(s->sending) {
            WAVEHDR *h=s->sending;
            ULONG accepted=0,length=h->dwBufferLength-s->offset;
            NTSTATUS status;
            if(!length) {s->offset=0;s->sending=h->lpNext;continue;}
            status=RetroPcm(1,s->native,h->lpData+s->offset,length,0,&accepted);
            if(status || !accepted) break;
            s->offset+=accepted;
            if(s->offset!=h->dwBufferLength) break;
            s->offset=0;s->sending=h->lpNext;
        }
        RtlReleaseSRWLockExclusive(&s->lock);
        wave_finish(s,done);
        RetroNtDelayExecution(FALSE,&delay);
    }
    RetroPcm(5,s->native,NULL,0,0,NULL);
    RtlFreeHeap(NtCurrentTeb()->Peb->ProcessHeap,0,s);
    return 0;
}
LRESULT CALLBACK DriverProc(DWORD_PTR id,HDRVR driver,UINT message,LPARAM a,LPARAM b)
{
    switch(message) {
    case DRV_LOAD:case DRV_FREE:case DRV_ENABLE:case DRV_DISABLE:case DRV_OPEN:case DRV_CLOSE:return 1;
    case DRV_QUERYCONFIGURE:return 0;
    default:return 0;
    }
}
DWORD WINAPI wodMessage(UINT device,UINT message,DWORD_PTR user,DWORD_PTR a,DWORD_PTR b)
{
    struct wave_stream *s=(void *)user;
    switch(message) {
    case DRVM_INIT:case DRVM_EXIT:case DRVM_ENABLE:case DRVM_DISABLE:return 0;
    case WODM_GETNUMDEVS:return 1;
    case WODM_GETDEVCAPS: {
        WAVEOUTCAPSW caps={0};
        static const WCHAR name[]=L"RetroOS PCM output";
        unsigned int i;
        caps.wMid=0xff;caps.wPid=1;caps.vDriverVersion=0x100;
        for(i=0;i<sizeof(name)/sizeof(*name);i++) caps.szPname[i]=name[i];
        caps.dwFormats=0xfff;caps.wChannels=2;caps.dwSupport=WAVECAPS_VOLUME|WAVECAPS_LRVOLUME;
        memcpy((void *)a,&caps,b<sizeof(caps)?b:sizeof(caps));return 0;
    }
    case DRVM_MAPPER_PREFERRED_GET:
        if(a) *(DWORD *)a=0;if(b) *(DWORD *)b=0;return 0;
    case WODM_OPEN: {
        WAVEOPENDESC *desc=(void *)a;
        const WAVEFORMATEX *f=desc->lpFormat;
        HANDLE thread;ULONG format[3];NTSTATUS status;
        if(device!=0 && device!=(UINT)-1 && device!=65535) return MMSYSERR_BADDEVICEID;
        if(f->wFormatTag!=WAVE_FORMAT_PCM || (f->nChannels!=1 && f->nChannels!=2) ||
           (f->wBitsPerSample!=8 && f->wBitsPerSample!=16) || f->nSamplesPerSec<4000 ||
           f->nSamplesPerSec>192000 || f->nBlockAlign!=f->nChannels*f->wBitsPerSample/8 ||
           f->nAvgBytesPerSec!=f->nSamplesPerSec*f->nBlockAlign) return WAVERR_BADFORMAT;
        if(b&WAVE_FORMAT_QUERY) return 0;
        s=RtlAllocateHeap(NtCurrentTeb()->Peb->ProcessHeap,HEAP_ZERO_MEMORY,sizeof(*s));
        if(!s) return MMSYSERR_NOMEM;
        s->desc=*desc;s->flags=b;s->format=*f;
        format[0]=f->nSamplesPerSec;format[1]=f->nChannels;format[2]=f->wBitsPerSample;
        status=RetroPcm(0,0,format,0,0,&s->native);
        if(!status) status=RetroNtCreateThreadEx(&thread,THREAD_ALL_ACCESS,NULL,GetCurrentProcess(),
            (void *)wave_thread,s,0,0,0,0,NULL);
        if(status) {
            if(s->native) RetroPcm(5,s->native,NULL,0,0,NULL);
            RtlFreeHeap(NtCurrentTeb()->Peb->ProcessHeap,0,s);return MMSYSERR_NOMEM;
        }
        RetroPcm(6,s->native,(void *)wave_volume,0,0,NULL);
        RetroNtClose(thread);*(DWORD_PTR *)user=(DWORD_PTR)s;
        wave_notify(s,WOM_OPEN,NULL);return 0;
    }
    case WODM_CLOSE: {
        struct wave_stream saved;
        RtlAcquireSRWLockExclusive(&s->lock);
        if(s->head) {RtlReleaseSRWLockExclusive(&s->lock);return WAVERR_STILLPLAYING;}
        saved=*s;s->closing=TRUE;RtlReleaseSRWLockExclusive(&s->lock);
        wave_notify(&saved,WOM_CLOSE,NULL);return 0;
    }
    case WODM_PREPARE: ((WAVEHDR *)a)->dwFlags|=WHDR_PREPARED;return 0;
    case WODM_UNPREPARE:
        if(((WAVEHDR *)a)->dwFlags&WHDR_INQUEUE) return WAVERR_STILLPLAYING;
        ((WAVEHDR *)a)->dwFlags&=~WHDR_PREPARED;return 0;
    case WODM_WRITE: {
        WAVEHDR *h=(void *)a;
        if(!(h->dwFlags&WHDR_PREPARED)) return WAVERR_UNPREPARED;
        if(h->dwFlags&WHDR_INQUEUE) return WAVERR_STILLPLAYING;
        if(h->dwFlags&(WHDR_BEGINLOOP|WHDR_ENDLOOP)) return MMSYSERR_NOTSUPPORTED;
        if(h->dwBufferLength%s->format.nBlockAlign) return MMSYSERR_INVALPARAM;
        RtlAcquireSRWLockExclusive(&s->lock);
        h->dwFlags=(h->dwFlags&~WHDR_DONE)|WHDR_INQUEUE;h->lpNext=NULL;
        if(s->tail) s->tail->lpNext=h;else s->head=h;
        s->tail=h;if(!s->sending) s->sending=h;
        RtlReleaseSRWLockExclusive(&s->lock);return 0;
    }
    case WODM_PAUSE:case WODM_RESTART:
        RetroPcm(4,s->native,(void *)(message==WODM_PAUSE),0,0,NULL);return 0;
    case WODM_RESET: {
        WAVEHDR *done;
        RtlAcquireSRWLockExclusive(&s->lock);
        RetroPcm(3,s->native,NULL,0,0,NULL);
        done=s->head;s->head=s->tail=s->sending=NULL;s->offset=0;s->completed=0;
        RtlReleaseSRWLockExclusive(&s->lock);wave_finish(s,done);return 0;
    }
    case WODM_GETPOS: {
        MMTIME *time=(void *)a;ULONGLONG position=0;LARGE_INTEGER value;
        RetroPcm(2,s->native,NULL,0,0,&position);
        value.QuadPart=position;
        if(time->wType==TIME_SAMPLES) time->u.sample=(DWORD)RtlExtendedLargeIntegerDivide(value.QuadPart,s->format.nBlockAlign,NULL);
        else if(time->wType==TIME_MS) {value.QuadPart=position*1000;time->u.ms=(DWORD)RtlExtendedLargeIntegerDivide(value.QuadPart,s->format.nAvgBytesPerSec,NULL);}
        else {time->wType=TIME_BYTES;time->u.cb=position;}return 0;
    }
    case WODM_GETVOLUME: *(DWORD *)a=wave_volume;return 0;
    case WODM_SETVOLUME:
        wave_volume=a;return RetroPcm(6,0,(void *)a,0,0,NULL)?MMSYSERR_ERROR:0;
    default:return MMSYSERR_NOTSUPPORTED;
    }
}
