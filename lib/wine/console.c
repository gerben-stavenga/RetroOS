/* Wine console device marshalling. RetroOS owns cells, codepages and input. */
#include "wine/condrv.h"
extern NTSTATUS WINAPI RetroConsole(ULONG,const ULONG *,void *,ULONG,ULONG *);
extern ULONG WINAPI RetroFileKind(ULONG);
extern NTSTATUS WINAPI RetroNtDelayExecution(BOOLEAN,const LARGE_INTEGER *);

NTSTATUS WINAPI RetroNtDeviceIoControlFile(HANDLE handle,HANDLE event,PIO_APC_ROUTINE apc,
    void *context,IO_STATUS_BLOCK *io,ULONG code,void *input,ULONG input_size,
    void *output,ULONG output_size)
{
    ULONG p[8]={0},info[8]={0},count=0,bytes=0,op;
    NTSTATUS status=STATUS_SUCCESS;
    ULONG value=HandleToULong(handle);
    if(!io || (input_size && !input) || (output_size && !output)) return STATUS_INVALID_PARAMETER;
    io->Information=0;
    if(event || apc) return io->Status=STATUS_NOT_SUPPORTED;
    if(value!=0x7c000001 && !(value==0x40000000 ||
       ((value & 0xffff0000)==0x40000000 && RetroFileKind(value & 65535)==2)))
        return io->Status=STATUS_INVALID_HANDLE;
    switch(code) {
    case IOCTL_CONDRV_GET_MODE:
    case IOCTL_CONDRV_GET_INPUT_INFO:
    case IOCTL_CONDRV_GET_OUTPUT_INFO:
        status=RetroConsole(code==IOCTL_CONDRV_GET_INPUT_INFO?0:2,p,info,0,&count);
        if(status) break;
        if(code==IOCTL_CONDRV_GET_INPUT_INFO) {
            if(output_size<sizeof(struct condrv_input_info)) return io->Status=STATUS_BUFFER_TOO_SMALL;
            memcpy(output,info,sizeof(struct condrv_input_info));bytes=sizeof(struct condrv_input_info);
        } else if(code==IOCTL_CONDRV_GET_MODE) {
            if(output_size<sizeof(ULONG)) return io->Status=STATUS_BUFFER_TOO_SMALL;
            *(ULONG *)output=info[value==0x40000000?5:6];bytes=sizeof(ULONG);
        } else {
            struct condrv_output_info *o=output;
            if(output_size<sizeof(*o)) return io->Status=STATUS_BUFFER_TOO_SMALL;
            memset(o,0,sizeof(*o));o->cursor_size=100;o->cursor_visible=1;
            o->cursor_x=info[0];o->cursor_y=info[1];o->width=info[2];o->height=info[3];o->attr=info[4];
            o->win_right=o->width-1;o->win_bottom=o->height-1;
            o->max_width=o->width;o->max_height=o->height;o->font_width=8;o->font_height=16;
            bytes=sizeof(*o);
        }
        break;
    case IOCTL_CONDRV_SET_INPUT_INFO: {
        const struct condrv_input_info_params *i=input;
        if(input_size!=sizeof(*i)) return io->Status=STATUS_INVALID_PARAMETER;
        p[0]=i->mask;p[1]=i->info.input_cp;p[2]=i->info.output_cp;
        status=RetroConsole(1,p,NULL,0,&count);break;
    }
    case IOCTL_CONDRV_SET_MODE:
        if(input_size!=sizeof(ULONG)) return io->Status=STATUS_INVALID_PARAMETER;
        p[0]=value==0x40000000?0:1;p[1]=*(ULONG *)input;
        status=RetroConsole(3,p,NULL,0,&count);break;
    case IOCTL_CONDRV_SET_OUTPUT_INFO: {
        const struct condrv_output_info_params *i=input;
        if(input_size!=sizeof(*i)) return io->Status=STATUS_INVALID_PARAMETER;
        if(i->mask & ~SET_CONSOLE_OUTPUT_INFO_CURSOR_POS) return io->Status=STATUS_NOT_SUPPORTED;
        p[0]=i->info.cursor_x;p[1]=i->info.cursor_y;
        status=RetroConsole(4,p,NULL,0,&count);break;
    }
    case IOCTL_CONDRV_WRITE_FILE:
    case IOCTL_CONDRV_WRITE_CONSOLE:
        if(code==IOCTL_CONDRV_WRITE_CONSOLE && (input_size & 1)) return io->Status=STATUS_INVALID_PARAMETER;
        p[0]=code==IOCTL_CONDRV_WRITE_FILE;
        status=RetroConsole(5,p,input,p[0]?input_size:input_size/2,&count);
        if(!status) bytes=input_size;
        break;
    case IOCTL_CONDRV_READ_OUTPUT: {
        const struct condrv_output_params *i=input;
        SMALL_RECT *r=output;
        ULONG width,height;
        if(input_size!=sizeof(*i) || output_size<sizeof(*r) || i->mode!=CHAR_INFO_MODE_TEXTATTR || !i->width)
            return io->Status=STATUS_INVALID_PARAMETER;
        status=RetroConsole(2,p,info,0,&count);if(status) break;
        if(i->x>=info[2] || i->y>=info[3]) return io->Status=STATUS_INVALID_PARAMETER;
        width=min(i->width,info[2]-i->x);
        height=min((output_size-sizeof(*r))/sizeof(char_info_t)/i->width,info[3]-i->y);
        p[0]=i->x;p[1]=i->y;p[2]=width;p[3]=height;
        status=RetroConsole(6,p,r+1,width*height,&count);
        if(!status){r->Left=i->x;r->Top=i->y;r->Right=i->x+width-1;r->Bottom=i->y+height-1;
            bytes=sizeof(*r)+count*sizeof(char_info_t);}
        break;
    }
    case IOCTL_CONDRV_READ_INPUT:
    case IOCTL_CONDRV_PEEK: {
        INPUT_RECORD *r=output;
        if(output_size<sizeof(*r)) return io->Status=STATUS_INVALID_PARAMETER;
        p[0]=code==IOCTL_CONDRV_PEEK;
        do {
            status=RetroConsole(7,p,info,0,&count);
            if(status || count || p[0]) break;
            { LARGE_INTEGER delay;delay.QuadPart=-10000;status=RetroNtDelayExecution(FALSE,&delay); }
        } while(!status);
        if(!status && count){
            memset(r,0,sizeof(*r));r->EventType=KEY_EVENT;
            r->Event.KeyEvent.bKeyDown=info[0];r->Event.KeyEvent.wRepeatCount=info[1];
            r->Event.KeyEvent.wVirtualKeyCode=info[2];r->Event.KeyEvent.wVirtualScanCode=info[3];
            r->Event.KeyEvent.uChar.UnicodeChar=info[4];r->Event.KeyEvent.dwControlKeyState=info[5];
            bytes=sizeof(*r);
        }
        break;
    }
    case IOCTL_CONDRV_FLUSH:
        status=RetroConsole(8,p,NULL,0,&count);break;
    case IOCTL_CONDRV_GET_INPUT_COUNT:
        if(output_size<sizeof(ULONG)) return io->Status=STATUS_BUFFER_TOO_SMALL;
        status=RetroConsole(9,p,NULL,0,output);if(!status) bytes=sizeof(ULONG);break;
    default: status=STATUS_NOT_SUPPORTED;break;
    }
    io->Information=bytes;
    return io->Status=status;
}
