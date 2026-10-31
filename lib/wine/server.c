/*
 * NTDLL directory and file functions
 *
 * Copyright 1993 Erik Bos
 * Copyright 2003 Eric Pouech
 * Copyright 1996, 2004 Alexandre Julliard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* Wine protocol marshalling. Object ownership lives behind RetroUserObject. */
#include <stdarg.h>
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "ntuser.h"
#include "wine/server.h"

_Static_assert(sizeof(union generic_request)==64, "Wine request union changed");
_Static_assert(MSG_HARDWARE==7, "Update hardware message type");
_Static_assert(offsetof(input_shm_t,keystate)==52 && offsetof(input_shm_t,keystate_lock)==308, "Update input key state offsets");
_Static_assert(offsetof(desktop_shm_t,keystate)==32, "Update desktop key state offset");
_Static_assert(MSG_POSTED==6, "Update RetroQueue message types for this Wine protocol");
struct object_info { ULONG handle, kind, flags, name_bytes; struct obj_locator locator; WCHAR name[256]; };
extern NTSTATUS WINAPI RetroUserObject(ULONG,ULONG,const WCHAR *,ULONG,ULONG,struct object_info *);
extern NTSTATUS WINAPI RetroQueue(ULONG,const ULONG *,ULONG *);
extern NTSTATUS WINAPI RetroCursor(const ULONG *,ULONG *);
extern NTSTATUS WINAPI RetroAtom(ULONG,ULONG,const WCHAR *,ULONG,ULONG *);
extern NTSTATUS WINAPI RetroWindowTree(ULONG,const ULONG *,ULONG *);
extern NTSTATUS WINAPI RetroWindow(ULONG,ULONG,const WCHAR *,ULONG,ULONG,ULONGLONG *);
extern NTSTATUS WINAPI RetroClass(ULONG,const WCHAR *,ULONG,const ULONG *,ULONG *);
extern void WINAPI RetroUnsupported(const char *);

NTSTATUS WINAPI RetroNtOpenDirectoryObject(HANDLE *out, ACCESS_MASK access, const OBJECT_ATTRIBUTES *attr)
{
    static const WCHAR path[] = L"\\Sessions\\0\\Windows\\WindowStations";
    struct object_info info;
    NTSTATUS status;
    unsigned int i;
    if (!out || !attr || attr->Length != sizeof(*attr) || !attr->ObjectName) return STATUS_INVALID_PARAMETER;
    if (attr->RootDirectory) return STATUS_NOT_SUPPORTED;
    if (attr->ObjectName->Length != sizeof(path)-sizeof(WCHAR) || !attr->ObjectName->Buffer) return STATUS_OBJECT_NAME_NOT_FOUND;
    for (i=0;i<ARRAY_SIZE(path)-1;i++)
    {
        WCHAR a=attr->ObjectName->Buffer[i], b=path[i];
        if (attr->Attributes & OBJ_CASE_INSENSITIVE) { if(a>='A'&&a<='Z') a+=32; if(b>='A'&&b<='Z') b+=32; }
        if(a!=b) return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    if (access & ~(1|2|4|READ_CONTROL)) return STATUS_ACCESS_DENIED;
    status=RetroUserObject(11,0,path,sizeof(path)-2,0,&info);
    if(!status) *out=ULongToHandle(info.handle);
    return status;
}

NTSTATUS WINAPI RetroServerCall(struct __server_request_info *data)
{
    union generic_request request;
    struct object_info info;
    const WCHAR *name=NULL;
    unsigned int length=0, op=~0u, handle=0, flags=0, capacity;
    NTSTATUS status;
    if(!data) return STATUS_INVALID_PARAMETER;
    request=data->u.req;
    capacity=request.request_header.reply_size;
    if(data->data_count>1) return STATUS_NOT_SUPPORTED;
    if(data->data_count) { name=data->data[0].ptr; length=data->data[0].size; }
    if(length!=request.request_header.request_size || (length && !name)) return STATUS_INVALID_PARAMETER;
    if(request.request_header.req==REQ_get_thread_input || request.request_header.req==REQ_get_msg_queue || request.request_header.req==REQ_get_msg_queue_handle ||
       request.request_header.req==REQ_set_queue_mask || request.request_header.req==REQ_get_queue_status ||
       request.request_header.req==REQ_set_win_timer || request.request_header.req==REQ_kill_win_timer ||
       request.request_header.req==REQ_get_message || request.request_header.req==REQ_accept_hardware_message ||
       request.request_header.req==REQ_send_message || request.request_header.req==REQ_post_quit_message ||
       request.request_header.req==REQ_get_key_state || request.request_header.req==REQ_set_key_state)
    {
        ULONG params[10]={0},result[12]={0};
        unsigned int operation=0,i;
        switch(request.request_header.req) {
        case REQ_accept_hardware_message: operation=14;params[0]=request.accept_hardware_message_request.hw_id;break;
        case REQ_send_message:
            if(request.send_message_request.type!=MSG_POSTED || length) return STATUS_NOT_SUPPORTED;
            operation=15;params[0]=request.send_message_request.id;params[1]=request.send_message_request.win;
            params[2]=request.send_message_request.msg;
            params[3]=request.send_message_request.wparam;params[4]=request.send_message_request.wparam>>32;
            params[5]=request.send_message_request.lparam;params[6]=request.send_message_request.lparam>>32;break;
        case REQ_get_key_state: operation=16;params[0]=request.get_key_state_request.async;params[1]=request.get_key_state_request.key;break;
        case REQ_set_key_state:
            if(length!=256)return STATUS_INVALID_PARAMETER;
            operation=17;params[0]=request.set_key_state_request.async;params[1]=(ULONG)name;break;
        case REQ_post_quit_message: operation=18;params[0]=request.post_quit_message_request.exit_code;break;
        case REQ_get_thread_input: operation=7;params[0]=request.get_thread_input_request.tid;break;
        case REQ_get_msg_queue: operation=0; break;
        case REQ_get_msg_queue_handle: operation=1; break;
        case REQ_set_queue_mask:
            operation=2; params[0]=request.set_queue_mask_request.wake_mask; params[1]=request.set_queue_mask_request.changed_mask; break;
        case REQ_get_queue_status: operation=3; params[0]=request.get_queue_status_request.clear_bits; break;
        case REQ_set_win_timer:
            operation=4; params[0]=request.set_win_timer_request.win; params[1]=request.set_win_timer_request.msg;
            params[2]=request.set_win_timer_request.rate; params[3]=request.set_win_timer_request.id; params[4]=request.set_win_timer_request.id>>32;
            params[5]=request.set_win_timer_request.lparam; params[6]=request.set_win_timer_request.lparam>>32; break;
        case REQ_kill_win_timer:
            operation=5; params[0]=request.kill_win_timer_request.win; params[1]=request.kill_win_timer_request.msg;
            params[3]=request.kill_win_timer_request.id; params[4]=request.kill_win_timer_request.id>>32; break;
        case REQ_get_message:
            operation=6; params[0]=request.get_message_request.flags; params[1]=request.get_message_request.get_win;
            params[2]=request.get_message_request.get_first; params[3]=request.get_message_request.get_last;
            params[4]=request.get_message_request.hw_id; params[5]=request.get_message_request.wake_mask;
            params[6]=request.get_message_request.changed_mask; params[7]=request.get_message_request.internal; break;
        }
        status=RetroQueue(operation,params,result);
        for(i=0;i<sizeof(data->u.reply);i++) ((volatile BYTE *)&data->u.reply)[i]=0;
        data->u.reply.reply_header.error=status;
        if(!status) switch(operation) {
        case 16: data->u.reply.get_key_state_reply.state=result[0];break;
        case 7:
            data->u.reply.get_thread_input_reply.locator.id=(ULONGLONG)result[0]|((ULONGLONG)result[1]<<32);
            data->u.reply.get_thread_input_reply.locator.offset=(ULONGLONG)result[2]|((ULONGLONG)result[3]<<32); break;
        case 0:
            data->u.reply.get_msg_queue_reply.locator.id=(ULONGLONG)result[0]|((ULONGLONG)result[1]<<32);
            data->u.reply.get_msg_queue_reply.locator.offset=(ULONGLONG)result[2]|((ULONGLONG)result[3]<<32); break;
        case 1: data->u.reply.get_msg_queue_handle_reply.handle=result[0]; break;
        case 2: data->u.reply.set_queue_mask_reply.wake_bits=result[0]; data->u.reply.set_queue_mask_reply.changed_bits=result[1]; break;
        case 3: data->u.reply.get_queue_status_reply.wake_bits=result[0]; data->u.reply.get_queue_status_reply.changed_bits=result[1]; break;
        case 4: data->u.reply.set_win_timer_reply.id=(ULONGLONG)result[0]|((ULONGLONG)result[1]<<32); break;
        case 6:
            data->u.reply.get_message_reply.win=result[0]; data->u.reply.get_message_reply.msg=result[1];
            data->u.reply.get_message_reply.wparam=(ULONGLONG)result[2]|((ULONGLONG)result[3]<<32);
            data->u.reply.get_message_reply.lparam=(ULONGLONG)result[4]|((ULONGLONG)result[5]<<32);
            data->u.reply.get_message_reply.type=result[6]; data->u.reply.get_message_reply.x=result[7];
            data->u.reply.get_message_reply.y=result[8]; data->u.reply.get_message_reply.time=result[9];
            if(result[6]==MSG_HARDWARE) {
                struct hardware_msg_data hardware={0};
                data->u.reply.get_message_reply.total=sizeof(hardware);
                if(capacity<sizeof(hardware) || !data->reply_data) {
                    status=STATUS_BUFFER_OVERFLOW;data->u.reply.reply_header.error=status;break;
                }
                hardware.hw_id=result[10]; hardware.source.device=IMDT_KEYBOARD;hardware.source.origin=IMO_HARDWARE;
                memcpy(data->reply_data,&hardware,sizeof(hardware));
                data->u.reply.reply_header.reply_size=sizeof(hardware);
            }
            break;
        }
        return status;
    }
    if(request.request_header.req==REQ_set_foreground_window || request.request_header.req==REQ_set_active_window ||
       request.request_header.req==REQ_set_focus_window || request.request_header.req==REQ_set_capture_window)
    {
        ULONG params[10]={0},result[12]={0}; unsigned int i,operation;
        switch(request.request_header.req){
        case REQ_set_foreground_window: operation=10;params[0]=request.set_foreground_window_request.handle;params[1]=request.set_foreground_window_request.internal;break;
        case REQ_set_active_window: operation=11;params[0]=request.set_active_window_request.handle;break;
        case REQ_set_focus_window: operation=12;params[0]=request.set_focus_window_request.handle;break;
        default: operation=13;params[0]=request.set_capture_window_request.handle;params[1]=request.set_capture_window_request.flags;break;
        }
        status=RetroQueue(operation,params,result);
        for(i=0;i<sizeof(data->u.reply);i++)((volatile BYTE *)&data->u.reply)[i]=0;
        data->u.reply.reply_header.error=status;
        switch(operation){
        case 10: data->u.reply.set_foreground_window_reply.previous=result[0];data->u.reply.set_foreground_window_reply.send_msg_old=result[1];data->u.reply.set_foreground_window_reply.send_msg_new=result[2];break;
        case 11: data->u.reply.set_active_window_reply.previous=result[0];break;
        case 12: data->u.reply.set_focus_window_reply.previous=result[0];break;
        case 13: data->u.reply.set_capture_window_reply.previous=result[0];data->u.reply.set_capture_window_reply.full_handle=result[1];break;
        }
        return status;
    }
    if(request.request_header.req==REQ_set_caret_window || request.request_header.req==REQ_set_caret_info)
    {
        ULONG params[10]={0},result[12]={0}; unsigned int i,operation;
        if(request.request_header.req==REQ_set_caret_window){
            operation=8;params[0]=request.set_caret_window_request.handle;
            params[1]=request.set_caret_window_request.width;params[2]=request.set_caret_window_request.height;
        }else{
            operation=9;params[0]=request.set_caret_info_request.handle;params[1]=request.set_caret_info_request.flags;
            params[2]=request.set_caret_info_request.x;params[3]=request.set_caret_info_request.y;
            params[4]=request.set_caret_info_request.hide;params[5]=request.set_caret_info_request.state;
        }
        status=RetroQueue(operation,params,result);
        for(i=0;i<sizeof(data->u.reply);i++)((volatile BYTE *)&data->u.reply)[i]=0;
        data->u.reply.reply_header.error=status;
        /* Both protocol replies have the same handle/rect/hide/state layout. */
        data->u.reply.set_caret_info_reply.full_handle=result[0];
        data->u.reply.set_caret_info_reply.old_rect=(struct rectangle){result[1],result[2],result[3],result[4]};
        data->u.reply.set_caret_info_reply.old_hide=result[5];data->u.reply.set_caret_info_reply.old_state=result[6];
        return status;
    }
    if(request.request_header.req==REQ_get_window_layered_info)
    {
        ULONG params[16]={request.get_window_layered_info_request.handle},result[8]={0};unsigned int i;
        status=RetroWindowTree(15,params,result);
        for(i=0;i<sizeof(data->u.reply);i++)((volatile BYTE *)&data->u.reply)[i]=0;
        data->u.reply.reply_header.error=status;
        return status;
    }
    if(request.request_header.req==REQ_get_update_region || request.request_header.req==REQ_redraw_window)
    {
        ULONG params[16]={0},result[8]={0};unsigned int i,operation;
        if(request.request_header.req==REQ_get_update_region){
            operation=13;params[0]=request.get_update_region_request.window;params[1]=request.get_update_region_request.from_child;
            params[2]=request.get_update_region_request.flags;params[3]=(ULONG)data->reply_data;params[4]=data->reply_data?capacity:0;
        }else{
            operation=14;params[0]=request.redraw_window_request.window;params[1]=request.redraw_window_request.flags;
            params[2]=(ULONG)name;params[3]=length;
        }
        status=RetroWindowTree(operation,params,result);
        for(i=0;i<sizeof(data->u.reply);i++)((volatile BYTE *)&data->u.reply)[i]=0;
        data->u.reply.reply_header.error=status;
        if(operation==13){data->u.reply.get_update_region_reply.child=result[0];data->u.reply.get_update_region_reply.flags=result[1];
            data->u.reply.get_update_region_reply.total_size=result[2];if(!status)data->u.reply.reply_header.reply_size=result[2];}
        return status;
    }
    if(request.request_header.req==REQ_set_winstation_monitors)
    {
        struct object_info result;
        unsigned int i;
        status=RetroUserObject(13,0,name,length,request.set_winstation_monitors_request.increment,&result);
        for(i=0;i<sizeof(data->u.reply);i++)((volatile BYTE *)&data->u.reply)[i]=0;
        data->u.reply.reply_header.error=status;
        if(!status)data->u.reply.set_winstation_monitors_reply.serial=(ULONGLONG)result.handle|((ULONGLONG)result.kind<<32);
        return status;
    }
    if(request.request_header.req==REQ_set_parent)
    {
        ULONG params[16]={request.set_parent_request.handle,request.set_parent_request.parent},result[8]={0};unsigned int i;
        status=RetroWindowTree(12,params,result);
        for(i=0;i<sizeof(data->u.reply);i++)((volatile BYTE *)&data->u.reply)[i]=0;
        data->u.reply.reply_header.error=status;
        if(!status){data->u.reply.set_parent_reply.old_parent=result[0];data->u.reply.set_parent_reply.full_parent=result[1];}
        return status;
    }
    if(request.request_header.req==REQ_add_user_atom || request.request_header.req==REQ_get_user_atom_name)
    {
        ULONG result[131]={0};unsigned int i;
        if(request.request_header.req==REQ_add_user_atom)
            status=RetroAtom(0x100,0,name,length&~1u,result);
        else if(request.get_user_atom_name_request.atom<0xc000 || request.get_user_atom_name_request.atom>0xffff)
            status=STATUS_INVALID_HANDLE;
        else status=RetroAtom(0x103,request.get_user_atom_name_request.atom,NULL,0,result);
        for(i=0;i<sizeof(data->u.reply);i++)((volatile BYTE *)&data->u.reply)[i]=0;
        data->u.reply.reply_header.error=status;
        if(!status && request.request_header.req==REQ_add_user_atom)data->u.reply.add_user_atom_reply.atom=result[0];
        else if(!status){
            unsigned int size=data->reply_data?min(capacity,result[2]):0;
            data->u.reply.get_user_atom_name_reply.total=result[2];
            data->u.reply.reply_header.reply_size=size;
            for(i=0;i<size;i++)((BYTE *)data->reply_data)[i]=((BYTE *)(result+3))[i];
        }
        return status;
    }
    if(request.request_header.req==REQ_get_window_text || request.request_header.req==REQ_set_window_text)
    {
        ULONG params[16]={0},result[8]={0};unsigned int i,operation;
        if(request.request_header.req==REQ_get_window_text){operation=10;params[0]=request.get_window_text_request.handle;params[1]=(ULONG)data->reply_data;params[2]=data->reply_data?capacity:0;}
        else {operation=11;params[0]=request.set_window_text_request.handle;params[1]=(ULONG)name;params[2]=length;}
        status=RetroWindowTree(operation,params,result);
        for(i=0;i<sizeof(data->u.reply);i++)((volatile BYTE *)&data->u.reply)[i]=0;
        data->u.reply.reply_header.error=status;
        if(!status && operation==10){data->u.reply.get_window_text_reply.length=result[0];data->u.reply.reply_header.reply_size=result[1];}
        return status;
    }
    if(request.request_header.req==REQ_get_window_children_from_point)
    {
        const struct get_window_children_from_point_request *r=&request.get_window_children_from_point_request;
        ULONG params[16]={r->parent,r->x,r->y,r->dpi,(ULONG)data->reply_data,data->reply_data?capacity/4:0},result[8]={0};unsigned int i;
        status=RetroWindowTree(9,params,result);
        for(i=0;i<sizeof(data->u.reply);i++)((volatile BYTE *)&data->u.reply)[i]=0;
        data->u.reply.reply_header.error=status;
        if(!status){data->u.reply.get_window_children_from_point_reply.count=result[0];data->u.reply.reply_header.reply_size=min(result[0],params[5])*4;}
        return status;
    }
    if(request.request_header.req==REQ_get_window_region || request.request_header.req==REQ_set_window_region)
    {
        ULONG params[16]={0},result[8]={0};unsigned int i,operation;
        if(request.request_header.req==REQ_get_window_region){operation=7;params[0]=request.get_window_region_request.window;params[1]=request.get_window_region_request.surface;params[2]=(ULONG)data->reply_data;params[3]=data->reply_data?capacity:0;}
        else {operation=8;params[0]=request.set_window_region_request.window;params[1]=request.set_window_region_request.redraw;params[2]=(ULONG)name;params[3]=length;}
        status=RetroWindowTree(operation,params,result);
        for(i=0;i<sizeof(data->u.reply);i++)((volatile BYTE *)&data->u.reply)[i]=0;
        data->u.reply.reply_header.error=status;
        if(operation==7){data->u.reply.get_window_region_reply.total_size=result[4];
            data->u.reply.get_window_region_reply.visible_rect=(struct rectangle){result[0],result[1],result[2],result[3]};
            if(!status)data->u.reply.reply_header.reply_size=result[4];}
        return status;
    }
    if(request.request_header.req==REQ_set_cursor)
    {
        const struct set_cursor_request *r=&request.set_cursor_request;
        ULONG params[9]={r->flags,r->handle,r->show_count,r->x,r->y,r->clip.left,r->clip.top,r->clip.right,r->clip.bottom},result[11]={0};
        unsigned int i;
        status=RetroCursor(params,result);
        for(i=0;i<sizeof(data->u.reply);i++)((volatile BYTE *)&data->u.reply)[i]=0;
        data->u.reply.reply_header.error=status;
        if(!status){
            struct set_cursor_reply *reply=&data->u.reply.set_cursor_reply;
            reply->prev_handle=result[0];reply->prev_count=result[1];reply->prev_x=result[2];reply->prev_y=result[3];
            reply->new_x=result[4];reply->new_y=result[5];reply->new_clip.left=result[6];reply->new_clip.top=result[7];
            reply->new_clip.right=result[8];reply->new_clip.bottom=result[9];reply->last_change=result[10];
        }
        return status;
    }
    if(request.request_header.req==REQ_init_window_info || request.request_header.req==REQ_set_window_info || request.request_header.req==REQ_get_window_info)
    {
        ULONG params[16]={0},result[8]={0};unsigned int operation,i;
        if(request.request_header.req==REQ_init_window_info){operation=4;params[0]=request.init_window_info_request.handle;params[1]=request.init_window_info_request.style;params[2]=request.init_window_info_request.ex_style;params[3]=request.init_window_info_request.is_unicode;}
        else if(request.request_header.req==REQ_get_window_info){operation=5;params[0]=request.get_window_info_request.handle;params[1]=request.get_window_info_request.offset;params[2]=request.get_window_info_request.size;}
        else {operation=6;params[0]=request.set_window_info_request.handle;params[1]=request.set_window_info_request.offset;params[2]=request.set_window_info_request.size;params[3]=request.set_window_info_request.new_info;params[4]=request.set_window_info_request.new_info>>32;}
        status=RetroWindowTree(operation,params,result);
        for(i=0;i<sizeof(data->u.reply);i++)((volatile BYTE *)&data->u.reply)[i]=0;
        data->u.reply.reply_header.error=status;
        if(!status && operation==5){data->u.reply.get_window_info_reply.info=(ULONGLONG)result[0]|((ULONGLONG)result[1]<<32);data->u.reply.get_window_info_reply.is_unicode=result[2];data->u.reply.get_window_info_reply.last_active=result[3];}
        if(!status && operation==6)data->u.reply.set_window_info_reply.old_info=(ULONGLONG)result[0]|((ULONGLONG)result[1]<<32);
        return status;
    }
    if(request.request_header.req==REQ_create_window || request.request_header.req==REQ_destroy_window ||
       request.request_header.req==REQ_get_window_list || request.request_header.req==REQ_set_window_pos)
    {
        ULONG params[16]={0},result[8]={0}; unsigned int operation,i;
        switch(request.request_header.req) {
        case REQ_create_window: {
            const struct create_window_request *r=&request.create_window_request;
            operation=0; params[0]=r->parent; params[1]=r->owner; params[2]=r->atom;
            params[3]=r->class_instance;params[4]=r->class_instance>>32;params[5]=r->instance;params[6]=r->instance>>32;
            params[7]=r->dpi_context;params[8]=r->style;params[9]=r->ex_style;params[11]=(ULONG)name;params[12]=length;break;
        }
        case REQ_destroy_window: operation=1;params[0]=request.destroy_window_request.handle;break;
        case REQ_get_window_list: {
            const struct get_window_list_request *r=&request.get_window_list_request;
            operation=2;params[0]=r->desktop;params[1]=r->handle;params[2]=r->tid;params[3]=r->children;
            params[4]=data->reply_data?capacity/sizeof(ULONG):0;params[5]=(ULONG)data->reply_data;break;
        }
        default: {
            const struct set_window_pos_request *r=&request.set_window_pos_request;
            operation=3;params[0]=r->handle;params[1]=r->previous;params[2]=r->swp_flags;params[3]=r->paint_flags;
            params[4]=r->window.left;params[5]=r->window.top;params[6]=r->window.right;params[7]=r->window.bottom;
            params[8]=r->client.left;params[9]=r->client.top;params[10]=r->client.right;params[11]=r->client.bottom;break;
        }
        }
        status=RetroWindowTree(operation,params,result);
        for(i=0;i<sizeof(data->u.reply);i++)((volatile BYTE *)&data->u.reply)[i]=0;
        data->u.reply.reply_header.error=status;
        if(operation==2) data->u.reply.get_window_list_reply.count=result[0];
        if(!status) switch(operation) {
        case 0: data->u.reply.create_window_reply.handle=result[0];data->u.reply.create_window_reply.parent=result[1];data->u.reply.create_window_reply.owner=result[2];data->u.reply.create_window_reply.extra=result[3];data->u.reply.create_window_reply.class_ptr=(ULONGLONG)result[4]|((ULONGLONG)result[5]<<32);break;
        case 2:data->u.reply.reply_header.reply_size=result[0]*sizeof(ULONG);break;
        case 3:data->u.reply.set_window_pos_reply.new_style=result[0];data->u.reply.set_window_pos_reply.new_ex_style=result[1];data->u.reply.set_window_pos_reply.surface_win=result[2];break;
        }
        return status;
    }
    if(request.request_header.req==REQ_get_visible_region || request.request_header.req==REQ_get_window_rectangles ||
       request.request_header.req==REQ_get_window_tree)
    {
        ULONG result[32]={0}, window;
        struct rectangle rect;
        unsigned int i;
        switch(request.request_header.req) {
        case REQ_get_visible_region: window=request.get_visible_region_request.window; break;
        case REQ_get_window_rectangles: window=request.get_window_rectangles_request.handle; break;
        case REQ_get_window_tree: window=request.get_window_tree_request.handle; break;
        default: window=0; break;
        }
        status=RetroWindow(5,window,NULL,0,0,(ULONGLONG *)result);
        for(i=0;i<sizeof(data->u.reply);i++) ((volatile BYTE *)&data->u.reply)[i]=0;
        rect.left=result[24];rect.top=result[25];rect.right=result[26];rect.bottom=result[27];
        if(!status) switch(request.request_header.req) {
        case REQ_get_visible_region:
            data->u.reply.get_visible_region_reply.top_win=result[0];
            data->u.reply.get_visible_region_reply.top_rect=rect;
            data->u.reply.get_visible_region_reply.win_rect=rect;
            if((result[1]&WS_VISIBLE) && rect.right>rect.left && rect.bottom>rect.top) {
                data->u.reply.get_visible_region_reply.total_size=sizeof(rect);
                if(capacity<sizeof(rect) || !data->reply_data) status=STATUS_BUFFER_OVERFLOW;
                else {
                    for(i=0;i<sizeof(rect);i++) ((BYTE *)data->reply_data)[i]=((BYTE *)&rect)[i];
                    data->u.reply.reply_header.reply_size=sizeof(rect);
                }
            }
            break;
        case REQ_get_window_rectangles:
            {
                struct rectangle client={result[28],result[29],result[30],result[31]};
                int x=0,y=0;
                switch(request.get_window_rectangles_request.relative) {
                case COORDS_CLIENT:x=client.left;y=client.top;break;
                case COORDS_WINDOW:x=rect.left;y=rect.top;break;
                case COORDS_PARENT:x=rect.left-(int)result[8];y=rect.top-(int)result[9];break;
                case COORDS_SCREEN:break;
                default:status=STATUS_INVALID_PARAMETER;break;
                }
                rect.left-=x;rect.right-=x;rect.top-=y;rect.bottom-=y;
                client.left-=x;client.right-=x;client.top-=y;client.bottom-=y;
                data->u.reply.get_window_rectangles_reply.window=rect;
                data->u.reply.get_window_rectangles_reply.client=client;
            }
            break;
        case REQ_get_window_tree:
            data->u.reply.get_window_tree_reply.parent=result[16];data->u.reply.get_window_tree_reply.owner=result[17];
            data->u.reply.get_window_tree_reply.next_sibling=result[18];data->u.reply.get_window_tree_reply.prev_sibling=result[19];
            data->u.reply.get_window_tree_reply.first_sibling=result[20];data->u.reply.get_window_tree_reply.last_sibling=result[21];
            data->u.reply.get_window_tree_reply.first_child=result[22];data->u.reply.get_window_tree_reply.last_child=result[23];break;
        }
        data->u.reply.reply_header.error=status;
        return status;
    }
    if(request.request_header.req==REQ_alloc_user_handle || request.request_header.req==REQ_free_user_handle)
    {
        ULONGLONG value=0;
        unsigned int i;
        if(request.request_header.req==REQ_alloc_user_handle)
            status=RetroWindow(3,0,NULL,0,request.alloc_user_handle_request.type,&value);
        else
            status=RetroWindow(4,request.free_user_handle_request.handle,NULL,0,request.free_user_handle_request.type,&value);
        for(i=0;i<sizeof(data->u.reply);i++) ((volatile unsigned char *)&data->u.reply)[i]=0;
        data->u.reply.reply_header.error=status;
        if(!status && request.request_header.req==REQ_alloc_user_handle) data->u.reply.alloc_user_handle_reply.handle=value;
        return status;
    }
    if(request.request_header.req==REQ_get_window_property ||
       request.request_header.req==REQ_set_window_property ||
       request.request_header.req==REQ_remove_window_property)
    {
        ULONGLONG value=0;
        ULONG atom, window, operation;
        unsigned int i;
        if(request.request_header.req==REQ_set_window_property) {
            operation=1; window=request.set_window_property_request.window;
            atom=request.set_window_property_request.atom; value=request.set_window_property_request.data;
        } else if(request.request_header.req==REQ_remove_window_property) {
            operation=2; window=request.remove_window_property_request.window; atom=request.remove_window_property_request.atom;
        } else {
            operation=0; window=request.get_window_property_request.window; atom=request.get_window_property_request.atom;
        }
        status=RetroWindow(operation,window,name,length,atom,&value);
        for(i=0;i<sizeof(data->u.reply);i++) ((volatile unsigned char *)&data->u.reply)[i]=0;
        data->u.reply.reply_header.error=status;
        if(!status && operation==0) data->u.reply.get_window_property_reply.data=value;
        if(!status && operation==2) data->u.reply.remove_window_property_reply.data=value;
        return status;
    }
    if(request.request_header.req==REQ_create_class || request.request_header.req==REQ_destroy_class)
    {
        ULONG params[10]={0}, result[8]={0};
        unsigned int i;
        if(request.request_header.req==REQ_create_class) {
            const struct create_class_request *r=&request.create_class_request;
            params[0]=r->local; params[1]=r->atom; params[2]=r->style;
            params[3]=r->instance; params[4]=r->instance>>32;
            params[5]=r->client_ptr; params[6]=r->client_ptr>>32;
            params[7]=r->cls_extra; params[8]=r->win_extra; params[9]=r->name_offset;
        } else {
            params[1]=request.destroy_class_request.atom;
            params[3]=request.destroy_class_request.instance;
            params[4]=request.destroy_class_request.instance>>32;
        }
        status=RetroClass(request.request_header.req==REQ_destroy_class,name,length,params,result);
        for(i=0;i<sizeof(data->u.reply);i++) ((volatile unsigned char *)&data->u.reply)[i]=0;
        data->u.reply.reply_header.error=status;
        if(!status && request.request_header.req==REQ_create_class) {
            data->u.reply.create_class_reply.locator.id=(ULONGLONG)result[0]|((ULONGLONG)result[1]<<32);
            data->u.reply.create_class_reply.locator.offset=(ULONGLONG)result[2]|((ULONGLONG)result[3]<<32);
            data->u.reply.create_class_reply.atom=result[4];
        } else if(!status) data->u.reply.destroy_class_reply.client_ptr=(ULONGLONG)result[6]|((ULONGLONG)result[7]<<32);
        return status;
    }
    switch(request.request_header.req)
    {
    case REQ_get_desktop_window: op=12; break;
    case REQ_get_process_winstation: op=0; break;
    case REQ_set_process_winstation: op=1; handle=request.set_process_winstation_request.handle; break;
    case REQ_create_winstation: op=2; handle=request.create_winstation_request.rootdir; flags=request.create_winstation_request.attributes; break;
    case REQ_open_winstation: op=3; handle=request.open_winstation_request.rootdir; break;
    case REQ_close_winstation: op=4; handle=request.close_winstation_request.handle; break;
    case REQ_create_desktop: if(request.create_desktop_request.flags) return STATUS_NOT_SUPPORTED; op=5; flags=request.create_desktop_request.attributes; break;
    case REQ_open_desktop: op=6; handle=request.open_desktop_request.winsta; break;
    case REQ_close_desktop: op=4; handle=request.close_desktop_request.handle; break;
    case REQ_get_thread_desktop: op=7; handle=request.get_thread_desktop_request.tid; break;
    case REQ_set_thread_desktop: op=8; handle=request.set_thread_desktop_request.handle; break;
    case REQ_set_user_object_info:
        op=(request.set_user_object_info_request.flags & SET_USER_OBJECT_SET_FLAGS)?10:9;
        handle=request.set_user_object_info_request.handle;
        flags=request.set_user_object_info_request.obj_flags;
        if(request.set_user_object_info_request.flags & SET_USER_OBJECT_GET_FULL_NAME) return STATUS_NOT_SUPPORTED;
        break;
    default:
    {
        char message[]="Wine server request 0x00000000";
        unsigned int n=request.request_header.req,i;
        for(i=0;i<8;i++) message[sizeof(message)-2-i]="0123456789abcdef"[(n>>(i*4))&15];
        RetroUnsupported(message);
        return STATUS_NOT_IMPLEMENTED;
    }
    }
    { unsigned int i; for(i=0;i<sizeof(data->u.reply);i++) ((volatile unsigned char *)&data->u.reply)[i]=0; }
    status=RetroUserObject(op,handle,name,length,flags,&info);
    if(!status)
    {
        switch(request.request_header.req)
        {
        case REQ_get_desktop_window:
            data->u.reply.get_desktop_window_reply.top_window=info.handle;
            data->u.reply.get_desktop_window_reply.msg_window=info.kind; break;
        case REQ_get_process_winstation: data->u.reply.get_process_winstation_reply.handle=info.handle; break;
        case REQ_create_winstation: data->u.reply.create_winstation_reply.handle=info.handle; break;
        case REQ_open_winstation: data->u.reply.open_winstation_reply.handle=info.handle; break;
        case REQ_create_desktop: data->u.reply.create_desktop_reply.handle=info.handle; break;
        case REQ_open_desktop: data->u.reply.open_desktop_reply.handle=info.handle; break;
        case REQ_get_thread_desktop:
            data->u.reply.get_thread_desktop_reply.handle=info.handle;
            data->u.reply.get_thread_desktop_reply.locator=info.locator; break;
        case REQ_set_thread_desktop: data->u.reply.set_thread_desktop_reply.locator=info.locator; break;
        case REQ_set_user_object_info:
            data->u.reply.set_user_object_info_reply.is_desktop=(info.kind==2);
            data->u.reply.set_user_object_info_reply.old_obj_flags=info.flags;
            if(capacity && data->reply_data) {
                unsigned int bytes=min(capacity,info.name_bytes);
                { unsigned int i; for(i=0;i<bytes;i++) ((volatile unsigned char *)data->reply_data)[i]=((unsigned char *)info.name)[i]; }
                data->u.reply.reply_header.reply_size=bytes;
                if(bytes<info.name_bytes) status=STATUS_BUFFER_OVERFLOW;
            }
            break;
        default: break;
        }
    }
    data->u.reply.reply_header.error=status;
    return status;
}

/* Per-handle NT search state remains in the DLL; the VFS primitive is indexed
 * enumeration only. RetroOS currently provides 64 descriptors per process. */
struct retro_directory_entry {
    ULONG size, attributes, mtime, name_bytes, short_bytes;
    WCHAR name[256], short_name[12];
};
_Static_assert(sizeof(struct retro_directory_entry)==556, "directory primitive ABI");
extern NTSTATUS WINAPI RetroFile(ULONG,ULONG,ULONG,ULONG,ULONG,ULONG,void *);
extern NTSTATUS WINAPI RetroNtSetEvent(HANDLE,LONG *);
static RTL_SRWLOCK directory_lock;
static struct directory_search { BOOL active; ULONG index; USHORT length; WCHAR mask[256]; } searches[64];
NTSTATUS RetroCloseFile(ULONG fd)
{
    NTSTATUS status;
    RtlAcquireSRWLockExclusive(&directory_lock);
    status=RetroFile(1,fd,0,0,0,0,NULL);
    if(!status && fd<ARRAY_SIZE(searches)) searches[fd].active=FALSE;
    RtlReleaseSRWLockExclusive(&directory_lock);
    return status;
}

/* Filename matcher from Wine 11 dlls/ntdll/unix/file.c (LGPL-2.1-or-later).
 * Only case folding is adapted to the portable NTDLL export. */
static BOOL is_wildcard(WCHAR c) { return c=='*'||c=='?'||c=='<'||c=='>'||c=='"'; }
static BOOLEAN match_filename_part( const WCHAR *name, const WCHAR *name_end, const WCHAR *mask, const WCHAR *mask_end )
{
    WCHAR c;

    while (name < name_end && mask < mask_end)
    {
        switch(*mask)
        {
        case '*':
            mask++;
            while (mask < mask_end && *mask == '*') mask++;  /* Skip consecutive '*' */
            if (mask == mask_end) return TRUE; /* end of mask is all '*', so match */

            while (name < name_end)
            {
                c = *mask == '"' ? '.' : *mask;
                if (!is_wildcard(c))
                {
                    while (name < name_end && (RtlUpcaseUnicodeChar(*name) != RtlUpcaseUnicodeChar(c))) name++;
                }
                if (match_filename_part( name, name_end, mask, mask_end )) return TRUE;
                ++name;
            }
            break;
        case '<':
        {
            const WCHAR *next_dot;
            BOOL had_dot = FALSE;

            ++mask;
            while (name < name_end)
            {
                next_dot = name;
                while (next_dot < name_end && *next_dot != '.') ++next_dot;
                if (next_dot == name_end && had_dot) break;
                if (next_dot < name_end)
                {
                    had_dot = TRUE;
                    ++next_dot;
                }
                if (mask < mask_end)
                {
                    while (name < next_dot)
                    {
                        c = *mask == '"' ? '.' : *mask;
                        if (!is_wildcard(c))
                        {
                            while (name < next_dot && (RtlUpcaseUnicodeChar(*name) != RtlUpcaseUnicodeChar(c))) name++;
                        }
                        if (match_filename_part( name, name_end, mask, mask_end )) return TRUE;
                        ++name;
                    }
                }
                name = next_dot;
            }
            break;
        }
        case '?':
            mask++;
            name++;
            break;
        case '>':
            mask++;
            if (*name == '.')
            {
                while (mask < mask_end && *mask == '>') mask++;
                if (mask == mask_end) name++;
            }
            else name++;
            break;
        default:
            c = *mask == '"' ? '.' : *mask;
            
            if ( RtlUpcaseUnicodeChar(c) != RtlUpcaseUnicodeChar(*name)) return FALSE;
            mask++;
            name++;
            break;
        }
    }
    while (mask < mask_end && (*mask == '*' || *mask == '<' || *mask == '"' || *mask == '>'))
        mask++;
    return (name == name_end && mask == mask_end);
}


/***********************************************************************
 *           match_filename
 *
 * Check a file name against a mask.
 *
 */
static BOOLEAN match_filename( const WCHAR *name, int length, const UNICODE_STRING *mask_str )
{
    /* Special handling for parent directory. */
    if (length == 2 && name[0] == '.' && name[1] == '.') --length;

    return match_filename_part( name, name + length, mask_str->Buffer,
                                mask_str->Buffer + mask_str->Length / sizeof(WCHAR));
}


NTSTATUS WINAPI RetroNtQueryDirectoryFile(HANDLE handle,HANDLE event,PIO_APC_ROUTINE apc,void *context,
    IO_STATUS_BLOCK *io,void *buffer,ULONG size,FILE_INFORMATION_CLASS class,BOOLEAN single,
    UNICODE_STRING *mask,BOOLEAN restart)
{
    struct retro_directory_entry entry;
    struct directory_search *search;
    UNICODE_STRING pattern,name;
    ULONG fd=HandleToULong(handle)&65535, name_offset, short_offset=0, bytes, i;
    NTSTATUS status;
    BOOL first;
    BYTE *out=buffer;
    if((HandleToULong(handle)&0xffff0000)!=0x40000000 || fd>=ARRAY_SIZE(searches)) return STATUS_INVALID_HANDLE;
    if(!io || !buffer || (mask && ((mask->Length&1) || mask->Length>510 || (mask->Length && !mask->Buffer)))) return STATUS_INVALID_PARAMETER;
    if(apc) return STATUS_NOT_SUPPORTED;
    switch(class) {
    case FileDirectoryInformation: name_offset=offsetof(FILE_DIRECTORY_INFORMATION,FileName); break;
    case FileFullDirectoryInformation: name_offset=offsetof(FILE_FULL_DIRECTORY_INFORMATION,FileName); break;
    case FileBothDirectoryInformation:
        name_offset=offsetof(FILE_BOTH_DIRECTORY_INFORMATION,FileName);
        short_offset=offsetof(FILE_BOTH_DIRECTORY_INFORMATION,ShortNameLength); break;
    case FileNamesInformation: name_offset=offsetof(FILE_NAMES_INFORMATION,FileName); break;
    case FileIdBothDirectoryInformation:
        name_offset=offsetof(FILE_ID_BOTH_DIRECTORY_INFORMATION,FileName);
        short_offset=offsetof(FILE_ID_BOTH_DIRECTORY_INFORMATION,ShortNameLength); break;
    case FileIdFullDirectoryInformation: name_offset=offsetof(FILE_ID_FULL_DIRECTORY_INFORMATION,FileName); break;
    case FileIdExtdBothDirectoryInformation:
        name_offset=offsetof(FILE_ID_EXTD_BOTH_DIRECTORY_INFORMATION,FileName);
        short_offset=offsetof(FILE_ID_EXTD_BOTH_DIRECTORY_INFORMATION,ShortNameLength); break;
    default: return STATUS_INVALID_INFO_CLASS;
    }
    if(size<name_offset) return STATUS_INFO_LENGTH_MISMATCH;
    RtlAcquireSRWLockExclusive(&directory_lock);
    search=&searches[fd];
    first=!search->active;
    if(first) {
        search->active=TRUE; search->index=0;
        search->length=mask && mask->Length ? mask->Length : 2;
        if(mask && mask->Length) for(i=0;i<mask->Length/2;i++) search->mask[i]=RtlUpcaseUnicodeChar(mask->Buffer[i]);
        else search->mask[0]='*';
    }
    if(restart) search->index=0;
    pattern.Buffer=search->mask; pattern.Length=pattern.MaximumLength=search->length;
    for(;;) {
        status=RetroFile(5,fd,0,0,search->index,0,&entry);
        if(status) { if(status==STATUS_NO_MORE_FILES && first) status=STATUS_NO_SUCH_FILE; break; }
        name.Buffer=entry.name; name.Length=name.MaximumLength=entry.name_bytes;
        if(!match_filename(name.Buffer,name.Length/2,&pattern)) {
            name.Buffer=entry.short_name; name.Length=name.MaximumLength=entry.short_bytes;
            if(!name.Length || !match_filename(name.Buffer,name.Length/2,&pattern)) { search->index++; continue; }
        }
        bytes=name_offset+entry.name_bytes;
        if(bytes>size) { status=STATUS_BUFFER_OVERFLOW; break; }
        for(i=0;i<bytes;i++) ((volatile BYTE *)out)[i]=0;
        *(ULONG *)(out+4)=search->index;
        if(class==FileNamesInformation) *(ULONG *)(out+8)=entry.name_bytes;
        else {
            FILE_DIRECTORY_INFORMATION *info=buffer;
            ULONGLONG time=entry.mtime ? ((ULONGLONG)entry.mtime+11644473600ULL)*10000000ULL : 0;
            info->CreationTime.QuadPart=info->LastAccessTime.QuadPart=info->LastWriteTime.QuadPart=info->ChangeTime.QuadPart=time;
            info->EndOfFile.QuadPart=entry.size;
            info->AllocationSize.QuadPart=((ULONGLONG)entry.size+4095)&~4095ULL;
            info->FileAttributes=entry.attributes; info->FileNameLength=entry.name_bytes;
        }
        if(short_offset) {
            out[short_offset]=entry.short_bytes;
            for(i=0;i<entry.short_bytes/2;i++) ((WCHAR *)(out+short_offset+2))[i]=entry.short_name[i];
        }
        for(i=0;i<entry.name_bytes/2;i++) ((WCHAR *)(out+name_offset))[i]=entry.name[i];
        search->index++;
        io->Information=bytes;
        status=STATUS_SUCCESS;
        break;
    }
    if(status) io->Information=0;
    io->Status=status;
    RtlReleaseSRWLockExclusive(&directory_lock);
    if(event) RetroNtSetEvent(event,NULL);
    return status;
}

#include "callbacks.c"

#include "threads.c"
