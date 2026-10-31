/* RetroOS display transport for Wine's portable USER/GDI implementation.
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */
#include "win32u_private.h"

__declspec(dllimport) NTSTATUS WINAPI RetroGraphics(ULONG,const ULONG *,ULONG *);

static UINT update_devices(const struct gdi_device_manager *manager,void *param)
{
    ULONG screen[3];
    struct pci_id pci={0};
    struct gdi_monitor monitor={0};
    DEVMODEW mode={0};
    NTSTATUS status=RetroGraphics(0,NULL,screen);
    if(status) return status;
    monitor.rc_monitor.right=monitor.rc_work.right=screen[0];
    monitor.rc_monitor.bottom=monitor.rc_work.bottom=screen[1];
    mode.dmSize=sizeof(mode);
    mode.dmFields=DM_POSITION|DM_BITSPERPEL|DM_PELSWIDTH|DM_PELSHEIGHT|DM_DISPLAYFREQUENCY;
    mode.dmBitsPerPel=32;mode.dmPelsWidth=screen[0];mode.dmPelsHeight=screen[1];mode.dmDisplayFrequency=60;
    manager->add_gpu("RetroOS compositor",&pci,NULL,param);
    manager->add_source("RetroOS desktop",DISPLAY_DEVICE_ATTACHED_TO_DESKTOP|DISPLAY_DEVICE_PRIMARY_DEVICE,96,param);
    manager->add_monitor(&monitor,param);
    manager->add_modes(&mode,1,&mode,param);
    return 0;
}

static LONG change_settings(DEVMODEW *modes,const WCHAR *primary,HWND hwnd,DWORD flags,void *param)
{
    ULONG screen[3];
    if(RetroGraphics(0,NULL,screen)) return DISP_CHANGE_FAILED;
    /* The virtual desktop currently has one mode. Do not claim a mode switch. */
    if(modes && ((modes->dmFields&DM_PELSWIDTH && modes->dmPelsWidth!=screen[0]) ||
                 (modes->dmFields&DM_PELSHEIGHT && modes->dmPelsHeight!=screen[1]) ||
                 (modes->dmFields&DM_BITSPERPEL && modes->dmBitsPerPel!=32))) return DISP_CHANGE_BADMODE;
    return DISP_CHANGE_SUCCESSFUL;
}

static void surface_clip(struct window_surface *surface,const RECT *rects,UINT count) {}
static void surface_destroy(struct window_surface *surface) {}
static BOOL surface_flush(struct window_surface *surface,const RECT *rect,const RECT *dirty,
                          const BITMAPINFO *info,const void *bits,BOOL shape_changed,
                          const BITMAPINFO *shape_info,const void *shape_bits)
{
    ULONG p[12]={0};
    RECT window;
    if(info->bmiHeader.biBitCount!=32 || info->bmiHeader.biCompression!=BI_RGB ||
       info->bmiHeader.biHeight>=0 || surface->shape_region || surface->alpha_mask ||
       surface->color_key!=CLR_INVALID) return FALSE;
    if(!get_window_rect(surface->hwnd,&window,96)) return FALSE;
    p[0]=HandleToULong(surface->hwnd);p[1]=window.left+surface->rect.left;p[2]=window.top+surface->rect.top;
    p[3]=info->bmiHeader.biWidth;p[4]=-info->bmiHeader.biHeight;p[5]=(ULONG)bits;
    p[6]=dirty->left;p[7]=dirty->top;p[8]=dirty->right;p[9]=dirty->bottom;
    p[10]=!!(get_window_long(surface->hwnd,GWL_STYLE)&WS_VISIBLE);
    return !RetroGraphics(1,p,NULL);
}
static const struct window_surface_funcs surface_funcs={surface_clip,surface_flush,surface_destroy};

static BOOL create_surface(HWND hwnd,BOOL layered,const RECT *rect,struct window_surface **surface)
{
    BITMAPINFO info={0};
    struct window_surface *previous=*surface;
    if(layered) return FALSE;
    if(previous && previous->funcs==&surface_funcs) return TRUE;
    info.bmiHeader.biSize=sizeof(info.bmiHeader);
    info.bmiHeader.biWidth=rect->right-rect->left;info.bmiHeader.biHeight=rect->top-rect->bottom;
    info.bmiHeader.biPlanes=1;info.bmiHeader.biBitCount=32;info.bmiHeader.biCompression=BI_RGB;
    *surface=window_surface_create(sizeof(**surface),&surface_funcs,hwnd,rect,&info,0);
    if(previous) window_surface_release(previous);
    return TRUE;
}
static void retro_destroy_window(HWND hwnd)
{
    ULONG p[12]={HandleToULong(hwnd)};
    RetroGraphics(2,p,NULL);
}
static void position_changed(HWND hwnd,HWND after,HWND owner,UINT flags,
                             const struct window_rects *rects,struct window_surface *surface)
{
    ULONG p[12]={HandleToULong(hwnd)};
    RECT window;
    if(!surface || surface->funcs!=&surface_funcs){retro_destroy_window(hwnd);return;}
    if(!get_window_rect(hwnd,&window,96))return;
    p[1]=window.left+surface->rect.left;p[2]=window.top+surface->rect.top;
    p[10]=!!(get_window_long(hwnd,GWL_STYLE)&WS_VISIBLE);
    p[11]=HandleToULong(after);
    RetroGraphics(3,p,NULL);
}
static const struct user_driver_funcs driver={
    .pUpdateDisplayDevices=update_devices,
    .pChangeDisplaySettings=change_settings,
    .pCreateWindowSurface=create_surface,
    .pWindowPosChanged=position_changed,
    .pDestroyWindow=retro_destroy_window,
};
void retro_graphics_init(void) { __wine_set_user_driver(&driver,WINE_GDI_DRIVER_VERSION); }
