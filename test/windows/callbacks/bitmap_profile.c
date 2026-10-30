#include <windows.h>
#include <stdio.h>
#include <string.h>
static unsigned errors;
#define CHECK(x) do {if(!(x)){++errors;printf("bitmap/profile check failed line %u\n",__LINE__);}}while(0)
static void CALLBACK close_message(HWND window, UINT msg, UINT_PTR id, DWORD ticks)
{
    HWND button=GetFocus();
    HWND dialog=GetParent(button);
    KillTimer(0,id);
    CHECK(GetDlgCtrlID(button)==IDCANCEL);
    CHECK(GetDlgItem(dialog,IDOK)!=0);
    CHECK(GetDlgItem(dialog,IDCANCEL)!=0);
    SendMessageW(dialog,WM_COMMAND,IDCANCEL,0);
}
static LRESULT CALLBACK paint_order_proc(HWND w, UINT m, WPARAM wp, LPARAM lp)
{
    if(m==WM_PAINT) {
        PAINTSTRUCT ps;
        RECT r;
        HDC dc=BeginPaint(w,&ps);
        GetClientRect(w,&r);
        FillRect(dc,&r,GetStockObject(GetParent(w)?BLACK_BRUSH:WHITE_BRUSH));
        EndPaint(w,&ps);
        return 0;
    }
    return DefWindowProcA(w,m,wp,lp);
}
int main(void)
{
    HDC dc=CreateCompatibleDC(0);
    HBITMAP bitmap=CreateBitmap(2,2,1,32,0);
    BITMAPINFO info;
    /* Two DWORD-aligned 24-bit rows, bottom-up: blue/white then red/green. */
    BYTE bits[16]={255,0,0,255,255,255,0,0, 0,0,255,0,255,0,0,0};
    const char ini[]="[Options]\r\nCount=0x2a\r\nLabel=\"hello\"\r\n";
    WCHAR text[32];
    HANDLE file;
    DWORD written;
    {
        HDC memory=CreateCompatibleDC(0);
        HBITMAP mono=CreateCompatibleBitmap(memory,9,2);
        HBITMAP color=CreateBitmap(9,2,1,8,0);
        HBITMAP same;
        BITMAP object;
        CHECK(GetObjectW(mono,sizeof(object),&object)==sizeof(object));
        CHECK(object.bmBitsPixel==1 && object.bmWidthBytes==2);
        SelectObject(memory,color);
        same=CreateCompatibleBitmap(memory,9,2);
        CHECK(GetObjectW(same,sizeof(object),&object)==sizeof(object));
        CHECK(object.bmBitsPixel==8 && object.bmWidthBytes==10);
        CHECK(GetBitmapBits(same,0,0)==20);
        DeleteDC(memory);DeleteObject(mono);DeleteObject(color);DeleteObject(same);
    }
    {
        RECT desktop;
        HWND root=GetDesktopWindow();
        CHECK(root && IsWindow(root) && IsWindowVisible(root));
        CHECK(GetWindowRect(root,&desktop));
        CHECK(desktop.right==GetSystemMetrics(SM_CXSCREEN));
        CHECK(desktop.bottom==GetSystemMetrics(SM_CYSCREEN));
        CHECK(GetSystemMetrics(SM_CXFULLSCREEN)==desktop.right);
        CHECK(GetSystemMetrics(SM_CYFULLSCREEN)==desktop.bottom-GetSystemMetrics(SM_CYCAPTION));
    }
    memset(&info,0,sizeof(info));
    info.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);
    info.bmiHeader.biWidth=2;info.bmiHeader.biHeight=2;
    info.bmiHeader.biPlanes=1;info.bmiHeader.biBitCount=24;
    CHECK(SelectObject(dc,bitmap)!=0);
    CHECK(SetDIBitsToDevice(dc,0,0,2,2,0,0,0,2,bits,&info,DIB_RGB_COLORS)==2);
    CHECK(GetPixel(dc,0,0)==RGB(255,0,0));CHECK(GetPixel(dc,1,0)==RGB(0,255,0));
    CHECK(GetPixel(dc,0,1)==RGB(0,0,255));CHECK(GetPixel(dc,1,1)==RGB(255,255,255));
    info.bmiHeader.biHeight=-2;
    CHECK(SetDIBitsToDevice(dc,0,0,2,2,0,0,0,2,bits,&info,DIB_RGB_COLORS)==2);
    CHECK(GetPixel(dc,0,0)==RGB(0,0,255));CHECK(GetPixel(dc,0,1)==RGB(255,0,0));
    CHECK(SetPixel(dc,1,1,RGB(22,33,44))==RGB(22,33,44));
    CHECK(GetPixel(dc,1,1)==RGB(22,33,44));
    /* Win32 and the Win16 bridge must read rendered pixels, not upload caches. */
    {
        BYTE readback[16];
        RECT border={0,0,2,2};
        BITMAP object;
        CHECK(GetObjectW(bitmap,sizeof(object),&object)==sizeof(object));
        CHECK(object.bmWidth==2 && object.bmHeight==2);
        CHECK(GetBitmapBits(bitmap,0,0)==16);
        memset(readback,0xa5,sizeof(readback));
        CHECK(GetBitmapBits(bitmap,7,readback)==0);
        CHECK(readback[0]==0xa5);
        CHECK(GetBitmapBits(bitmap,16,readback)==16);
        CHECK(readback[12]==44 && readback[13]==33 && readback[14]==22);
        CHECK(FrameRect(dc,&border,GetStockObject(WHITE_BRUSH)));
        CHECK(GetBitmapBits(bitmap,16,readback)==16);
        CHECK(readback[0]==255 && readback[13]==255 && readback[14]==255);
        /* Restore pixels needed by the following blit tests. */
        CHECK(SetDIBitsToDevice(dc,0,0,2,2,0,0,0,2,bits,&info,DIB_RGB_COLORS)==2);
        SetPixel(dc,1,1,RGB(22,33,44));
    }
    /* Four-bit DDB bright colors use the standard static palette. */
    {
        BYTE data[2]={0x89,0xaf}, readback[2]={0,0};
        HDC memory=CreateCompatibleDC(0);
        HBITMAP image=CreateBitmap(4,1,1,4,data);
        HGDIOBJ old=SelectObject(memory,image);
        CHECK(GetPixel(memory,0,0)==RGB(128,128,128));
        CHECK(GetPixel(memory,1,0)==RGB(255,0,0));
        CHECK(GetPixel(memory,2,0)==RGB(0,255,0));
        CHECK(GetPixel(memory,3,0)==RGB(255,255,255));
        CHECK(GetBitmapBits(image,2,readback)==2 && memcmp(data,readback,2)==0);
        SelectObject(memory,old);DeleteObject(image);DeleteDC(memory);
    }
    /* Intermediate indexed copies retain colour identities across a fade. */
    {
        struct {WORD version,count; PALETTEENTRY entries[2];} table={0x300,2,{{0,0,0,PC_RESERVED},{0,0,0,PC_RESERVED}}};
        PALETTEENTRY colors[2]={{255,0,0,PC_RESERVED},{0,255,0,PC_RESERVED}};
        BYTE indices[2]={10,11};
        HPALETTE palette=CreatePalette((LOGPALETTE *)&table);
        HDC source=CreateCompatibleDC(0), middle=CreateCompatibleDC(0);
        HBITMAP sb=CreateBitmap(2,1,1,8,indices), mb=CreateBitmap(2,1,1,8,0);
        HPALETTE old_source,old_middle,old_dst;
        SelectObject(source,sb);SelectObject(middle,mb);
        old_source=SelectPalette(source,palette,FALSE);
        old_middle=SelectPalette(middle,palette,FALSE);
        old_dst=SelectPalette(dc,palette,FALSE);
        CHECK(RealizePalette(source)==2);
        CHECK(BitBlt(middle,0,0,2,1,source,0,0,SRCCOPY));
        CHECK(GetPixel(middle,0,0)==0 && GetPixel(middle,1,0)==0);
        CHECK(SetPaletteEntries(palette,0,2,colors)==2);
        RealizePalette(source);
        CHECK(BitBlt(dc,0,0,2,1,middle,0,0,SRCCOPY));
        CHECK(GetPixel(dc,0,0)==RGB(255,0,0));
        CHECK(GetPixel(dc,1,0)==RGB(0,255,0));
        {
            PALETTEENTRY device[2], animated={0,0,255,0};
            CHECK(GetSystemPaletteEntries(dc,10,2,device)==2);
            CHECK(device[0].peRed==255 && device[1].peGreen==255);
            CHECK(AnimatePalette(palette,0,1,&animated));
            CHECK(GetSystemPaletteEntries(dc,10,2,device)==2);
            CHECK(device[0].peBlue==255 && device[0].peRed==0);
            CHECK(BitBlt(dc,0,0,2,1,middle,0,0,SRCCOPY));
            CHECK(GetPixel(dc,0,0)==RGB(0,0,255));
        }
        SelectPalette(source,old_source,FALSE);SelectPalette(middle,old_middle,FALSE);
        SelectPalette(dc,old_dst,FALSE);
        DeleteDC(source);DeleteDC(middle);DeleteObject(sb);DeleteObject(mb);DeleteObject(palette);
        CHECK(SetDIBitsToDevice(dc,0,0,2,2,0,0,0,2,bits,&info,DIB_RGB_COLORS)==2);
        SetPixel(dc,1,1,RGB(22,33,44));
    }
    /* Pattern brushes snapshot their bitmap and repeat with the DC origin. */
    {
        BYTE pattern_bits[16]={0,0,255,0, 0,255,0,0, 255,0,0,0, 255,255,255,0};
        HBITMAP image=CreateBitmap(2,2,1,32,pattern_bits);
        HBRUSH pattern=CreatePatternBrush(image);
        HDC target=CreateCompatibleDC(0);
        HBITMAP surface=CreateBitmap(4,4,1,32,0);
        RECT area={0,0,4,4};
        HGDIOBJ previous;
        HRGN clip;
        CHECK(pattern!=0);
        CHECK(DeleteObject(image));
        SelectObject(target,surface);
        CHECK(FillRect(target,&area,pattern));
        CHECK(GetPixel(target,0,0)==RGB(255,0,0));
        CHECK(GetPixel(target,1,0)==RGB(0,255,0));
        CHECK(GetPixel(target,0,1)==RGB(0,0,255));
        CHECK(GetPixel(target,3,3)==RGB(255,255,255));
        CHECK(SetBrushOrgEx(target,1,-1,0));
        CHECK(FillRect(target,&area,pattern));
        CHECK(GetPixel(target,0,0)==RGB(255,255,255));
        CHECK(GetPixel(target,0,1)==RGB(0,255,0));
        clip=CreateRectRgn(1,1,3,3);
        SelectClipRgn(target,clip);
        SetBrushOrgEx(target,0,0,0);
        CHECK(FillRect(target,&area,pattern));
        CHECK(GetPixel(target,0,0)==RGB(255,255,255));
        CHECK(GetPixel(target,2,2)==RGB(255,0,0));
        SelectClipRgn(target,0);
        previous=SelectObject(target,pattern);
        CHECK(PatBlt(target,0,0,4,4,PATINVERT));
        CHECK(PatBlt(target,0,0,4,4,PATINVERT));
        CHECK(GetPixel(target,2,2)==RGB(255,0,0));
        SelectObject(target,previous);
        DeleteObject(pattern);DeleteObject(clip);DeleteDC(target);DeleteObject(surface);
    }
    /* SRCCOPY respects source bounds and destination clips, ignores ROP2,
       and snapshots overlapping copies within the same bitmap. */
    {
        HDC dst=CreateCompatibleDC(0);
        HBITMAP db=CreateCompatibleBitmap(dst,4,4);
        HRGN clip=CreateRectRgn(1,1,3,3);
        int x,y;
        SelectObject(dst,db);
        for(y=0;y<4;++y) for(x=0;x<4;++x) SetPixel(dst,x,y,RGB(9,8,7));
        SelectClipRgn(dst,clip);
        SetROP2(dst,R2_BLACK);
        CHECK(BitBlt(dst,0,0,4,4,dc,-1,-1,SRCCOPY));
        CHECK(GetPixel(dst,1,1)==RGB(0,0,255));
        CHECK(GetPixel(dst,2,1)==RGB(255,255,255));
        CHECK(GetPixel(dst,2,2)==RGB(22,33,44));
        SelectClipRgn(dst,0);
        CHECK(GetPixel(dst,0,0)==RGB(9,8,7));
        CHECK(GetPixel(dst,3,3)==RGB(9,8,7));
        CHECK(BitBlt(dst,2,2,2,2,dst,1,1,SRCCOPY));
        CHECK(GetPixel(dst,2,2)==RGB(0,0,255));
        CHECK(GetPixel(dst,3,3)==RGB(22,33,44));
        /* Classic icon masks: preserve, invert, black and white. */
        SelectClipRgn(dst,0);SetROP2(dst,R2_COPYPEN);
        SetPixel(dst,0,0,RGB(10,20,30));SetPixel(dst,1,0,RGB(10,20,30));
        SetPixel(dst,0,1,RGB(10,20,30));SetPixel(dst,1,1,RGB(10,20,30));
        SetPixel(dc,0,0,RGB(255,255,255));SetPixel(dc,1,0,RGB(255,255,255));
        SetPixel(dc,0,1,0);SetPixel(dc,1,1,0);
        SetROP2(dst,R2_BLACK); /* BitBlt must ignore this. */
        CHECK(BitBlt(dst,0,0,2,2,dc,0,0,SRCAND));
        SetPixel(dc,0,0,0);SetPixel(dc,1,0,RGB(255,255,255));
        SetPixel(dc,0,1,0);SetPixel(dc,1,1,RGB(255,255,255));
        CHECK(BitBlt(dst,0,0,2,2,dc,0,0,SRCINVERT));
        CHECK(GetPixel(dst,0,0)==RGB(10,20,30));
        CHECK(GetPixel(dst,1,0)==RGB(245,235,225));
        CHECK(GetPixel(dst,0,1)==0);CHECK(GetPixel(dst,1,1)==RGB(255,255,255));
        {
            RECT edge={0,0,4,4};
            CHECK(FrameRect(dst,&edge,GetStockObject(WHITE_BRUSH)));
            CHECK(GetPixel(dst,0,0)==RGB(255,255,255));
            CHECK(GetPixel(dst,3,3)==RGB(255,255,255));
            CHECK(GetPixel(dst,2,2)==RGB(0,0,255));
        }
        DeleteObject(clip);DeleteDC(dst);DeleteObject(db);
    }
    {
        POINT previous;
        HBRUSH brush=CreateSolidBrush(RGB(1,2,3));
        CHECK(SetBrushOrgEx(dc,7,-3,&previous));
        CHECK(previous.x==0&&previous.y==0);
        CHECK(SetBrushOrgEx(dc,-2,9,&previous));
        CHECK(previous.x==7&&previous.y==-3);
        CHECK(UnrealizeObject(brush));
        CHECK(!UnrealizeObject((HGDIOBJ)0));
        DeleteObject(brush);
    }
    CHECK(DeleteDC(dc));CHECK(DeleteObject(bitmap));
    /* Rectangle honors selected brush/pen and excludes right/bottom edges. */
    {
        HDC rd=CreateCompatibleDC(0);
        HBITMAP rb=CreateCompatibleBitmap(rd,16,16);
        HBRUSH red=CreateSolidBrush(RGB(255,0,0));
        HPEN black=CreatePen(PS_SOLID,1,RGB(0,0,0));
        HGDIOBJ oldb,oldp;
        SelectObject(rd,rb);
        oldb=SelectObject(rd,red);oldp=SelectObject(rd,black);
        CHECK(Rectangle(rd,2,2,10,10));
        CHECK(GetPixel(rd,3,3)==RGB(255,0,0));
        CHECK(GetPixel(rd,2,2)==RGB(0,0,0));
        CHECK(GetPixel(rd,10,10)!=RGB(255,0,0));
        SetPixel(rd,4,4,RGB(0,0,255));
        SelectObject(rd,GetStockObject(NULL_BRUSH));
        CHECK(Rectangle(rd,2,2,10,10));
        CHECK(GetPixel(rd,4,4)==RGB(0,0,255));
        SelectObject(rd,red);SelectObject(rd,GetStockObject(NULL_PEN));
        CHECK(Rectangle(rd,2,2,10,10));
        CHECK(GetPixel(rd,2,2)==RGB(255,0,0));
        SelectObject(rd,oldb);SelectObject(rd,oldp);
        DeleteDC(rd);DeleteObject(rb);DeleteObject(red);DeleteObject(black);
    }
    /* Pending parent paint must precede child paint, even if the child
       was invalidated first, or the parent wipes out its finished pixels. */
    {
        WNDCLASSA wc={0};
        MSG msg;
        HWND parent,child;
        HDC pdc;
        wc.lpfnWndProc=paint_order_proc;wc.lpszClassName="PaintOrder";
        wc.hInstance=GetModuleHandleA(0);
        CHECK(RegisterClassA(&wc)!=0);
        parent=CreateWindowA("PaintOrder","",WS_POPUP|WS_VISIBLE,0,0,100,80,0,0,wc.hInstance,0);
        child=CreateWindowA("PaintOrder","",WS_CHILD|WS_VISIBLE,10,10,30,30,parent,0,wc.hInstance,0);
        UpdateWindow(parent);
        InvalidateRect(child,0,TRUE);
        InvalidateRect(parent,0,TRUE);
        CHECK(PeekMessageA(&msg,0,WM_PAINT,WM_PAINT,PM_REMOVE));
        CHECK(msg.hwnd==parent);DispatchMessageA(&msg);
        CHECK(PeekMessageA(&msg,0,WM_PAINT,WM_PAINT,PM_REMOVE));
        CHECK(msg.hwnd==child);DispatchMessageA(&msg);
        pdc=GetDC(parent);CHECK(GetPixel(pdc,15,15)==RGB(0,0,0));ReleaseDC(parent,pdc);
        DestroyWindow(parent);
        UnregisterClassA("PaintOrder",wc.hInstance);
    }
    /* Window DC copies must snapshot overlapping pixels, and scrolling must
       expose the vacated strip while preserving the copied content. */
    {
        HWND window=CreateWindowA("STATIC","",WS_POPUP|WS_VISIBLE,30,40,100,80,0,0,0,0);
        HDC wd;
        RECT area={0,0,8,8},update;
        POINT point={5,6};
        HCURSOR arrow=LoadCursorA(0,IDC_ARROW),old;
        int x,y,tab=24;
        DWORD extent;
        UpdateWindow(window);
        CHECK(ClientToScreen(window,&point));
        CHECK(point.x==35&&point.y==46);
        CHECK(ScreenToClient(window,&point));
        CHECK(point.x==5&&point.y==6);
        old=SetCursor(arrow);
        CHECK(GetCursor()==arrow);
        CHECK(ShowCursor(FALSE)==-1);
        CHECK(ShowCursor(TRUE)==0);
        CHECK(SetCursor(old)==arrow);
        wd=GetDC(window);
        for(y=0;y<8;++y) for(x=0;x<8;++x) SetPixel(wd,x,y,RGB(x+1,y+1,7));
        CHECK(ScrollWindow(window,2,0,&area,&area));
        CHECK(GetPixel(wd,2,3)==RGB(1,4,7));
        CHECK(GetPixel(wd,7,3)==RGB(6,4,7));
        CHECK(GetUpdateRect(window,&update,FALSE));
        CHECK(update.left==0&&update.top==0&&update.right==2&&update.bottom==8);
        extent=GetTabbedTextExtentA(wd,"A\tB",3,1,&tab);
        CHECK(TabbedTextOutA(wd,10,20,"A\tB",3,1,&tab,10)==extent);
        ReleaseDC(window,wd);
        DestroyWindow(window);
    }
    /* Group frames must not erase sibling controls; auto-radio buttons share
       state and painting regardless of whether the caller is PE or NE. */
    {
        HWND parent=CreateWindowA("STATIC","",WS_POPUP|WS_VISIBLE,0,0,250,80,0,0,0,0);
        HWND first=CreateWindowA("BUTTON","first",WS_CHILD|WS_VISIBLE|WS_GROUP|BS_AUTORADIOBUTTON,10,20,100,20,parent,(HMENU)1,0,0);
        HWND second=CreateWindowA("BUTTON","second",WS_CHILD|WS_VISIBLE|BS_AUTORADIOBUTTON,120,20,100,20,parent,(HMENU)2,0,0);
        HWND group=CreateWindowA("BUTTON","Choices",WS_CHILD|WS_VISIBLE|BS_GROUPBOX,0,0,240,60,parent,(HMENU)3,0,0);
        HDC cd;
        CHECK(parent&&first&&second&&group);
        SendMessageA(first,BM_CLICK,0,0);
        CHECK(SendMessageA(first,BM_GETCHECK,0,0)==BST_CHECKED);
        SendMessageA(second,BM_CLICK,0,0);
        CHECK(SendMessageA(first,BM_GETCHECK,0,0)==BST_UNCHECKED);
        CHECK(SendMessageA(second,BM_GETCHECK,0,0)==BST_CHECKED);
        UpdateWindow(parent);UpdateWindow(first);UpdateWindow(second);
        cd=GetDC(first);
        CHECK(GetPixel(cd,0,9)==RGB(0,0,0));
        UpdateWindow(group);
        CHECK(GetPixel(cd,0,9)==RGB(0,0,0));
        ReleaseDC(first,cd);DestroyWindow(parent);
    }
    /* Win16 installers reach the real combo edit by child ID 1001. Text
       entered there must also be returned through the combo itself. */
    {
        char value[64];
        HWND parent=CreateWindowA("STATIC","",WS_POPUP,0,0,300,200,0,0,0,0);
        HWND combo=CreateWindowA("COMBOBOX","",WS_CHILD|CBS_DROPDOWN,0,0,200,100,parent,(HMENU)100,0,0);
        HWND edit=GetDlgItem(combo,1001);
        CHECK(combo&&edit);
        CHECK(GetParent(edit)==combo);
        CHECK(SetWindowTextA(edit,"C:\\MPS\\CIVWIN"));
        CHECK(GetWindowTextA(combo,value,sizeof(value))==13);
        CHECK(strcmp(value,"C:\\MPS\\CIVWIN")==0);
        CHECK(SetWindowTextA(combo,"replacement"));
        CHECK(GetWindowTextA(edit,value,sizeof(value))==11);
        CHECK(strcmp(value,"replacement")==0);
        CHECK(SendMessageA(combo,CB_ADDSTRING,0,(LPARAM)"selected")==0);
        CHECK(SendMessageA(combo,CB_SETCURSEL,0,0)==0);
        CHECK(GetWindowTextA(edit,value,sizeof(value))==8);
        CHECK(strcmp(value,"selected")==0);
        CHECK(SendMessageA(combo,CB_SELECTSTRING,(WPARAM)-1,(LPARAM)"missing")==CB_ERR);
        CHECK(SendMessageA(combo,CB_GETCURSEL,0,0)==0);
        CHECK(SendMessageA(combo,CB_ADDSTRING,0,(LPARAM)"Second")==1);
        CHECK(SendMessageA(combo,CB_SELECTSTRING,(WPARAM)-1,(LPARAM)"sec")==1);
        CHECK(GetWindowTextA(edit,value,sizeof(value))==6);
        CHECK(strcmp(value,"Second")==0);
        CHECK(SendMessageA(combo,CB_FINDSTRINGEXACT,(WPARAM)-1,(LPARAM)"second")==1);
        CHECK(SendMessageA(combo,CB_FINDSTRINGEXACT,(WPARAM)-1,(LPARAM)"sec")==CB_ERR);
        CHECK(SendMessageA(combo,CB_SETCURSEL,(WPARAM)-1,0)==CB_ERR);
        CHECK(GetWindowTextA(combo,value,sizeof(value))==0);
        CHECK(DestroyWindow(parent));
        CHECK(!IsWindow(edit));
    }
    CHECK(SetTimer(0,0,20,close_message)!=0);
    CHECK(MessageBoxW(0,L"Choose Cancel.",L"Shared modal message",MB_OKCANCEL|MB_DEFBUTTON2)==IDCANCEL);
    file=CreateFileA("C:\\PROFILE.INI",GENERIC_WRITE,0,0,CREATE_ALWAYS,0,0);
    CHECK(file!=INVALID_HANDLE_VALUE);
    CHECK(WriteFile(file,ini,sizeof(ini)-1,&written,0));CHECK(CloseHandle(file));
    CHECK(GetPrivateProfileIntW(L"options",L"count",7,L"C:\\PROFILE.INI")==42);
    CHECK(GetPrivateProfileIntW(L"options",L"missing",7,L"C:\\PROFILE.INI")==7);
    CHECK(GetPrivateProfileStringW(L"options",L"label",L"fallback",text,32,L"C:\\PROFILE.INI")==5);
    CHECK(text[0]=='h'&&text[4]=='o'&&text[5]==0);
    CHECK(GetPrivateProfileStringW(L"options",L"label",L"",text,3,L"C:\\PROFILE.INI")==2);
    CHECK(text[0]=='h'&&text[1]=='e'&&text[2]==0);
    CHECK(GetPrivateProfileStringW(L"options",0,L"",text,32,L"C:\\PROFILE.INI")==12);
    CHECK(text[5]==0&&text[11]==0&&text[12]==0);
    CHECK(GetPrivateProfileStringW(L"options",0,L"",text,13,L"C:\\PROFILE.INI")==12);
    CHECK(text[11]==0&&text[12]==0);
    printf("WINCALLBACK %s bitmap/profile\n",errors?"FAIL":"PASS");return errors?1:0;
}
