#include <windows.h>
#include <stdio.h>
static unsigned errors;
#define CHECK(x) do {if(!(x)){++errors;printf("region check failed line %u\n",__LINE__);}}while(0)
int main(void)
{
    HRGN outer=CreateRectRgn(0,0,10,10),hole=CreateRectRgn(2,2,8,8),ring=CreateRectRgn(0,0,0,0),copy=CreateRectRgn(0,0,0,0);
    HDC dc=CreateCompatibleDC(0);
    HBITMAP bitmap=CreateCompatibleBitmap(dc,10,10);
    HBRUSH brush=CreateSolidBrush(RGB(33,44,55));
    RECT bounds,fill={0,0,10,10};
    HMENU menu=CreateMenu(), sub=CreatePopupMenu();
    CHECK(menu && sub);
    CHECK(AppendMenuA(sub,MF_STRING,42,"Answer"));
    CHECK(AppendMenuA(menu,MF_POPUP,(UINT)sub,"Actions"));
    CHECK(GetMenuItemCount(menu)==1);CHECK(GetSubMenu(menu,0)==sub);
    CHECK(GetMenuItemID(sub,0)==42);
    CHECK(EnableMenuItem(menu,42,MF_BYCOMMAND|MF_GRAYED)==0);
    CHECK((GetMenuState(sub,0,MF_BYPOSITION)&3)==MF_GRAYED);
    CHECK(CheckMenuItem(menu,42,MF_CHECKED)==0);
    CHECK(GetMenuState(menu,42,MF_BYCOMMAND)&MF_CHECKED);
    /* Reject cycles; recursive menu destruction must always terminate. */
    CHECK(!AppendMenuA(sub,MF_POPUP,(UINT)menu,"Cycle"));
    CHECK(DestroyMenu(menu));CHECK(!IsMenu(sub));
    CHECK(CombineRgn(ring,outer,hole,RGN_DIFF)==COMPLEXREGION);
    CHECK(PtInRegion(ring,0,0));CHECK(!PtInRegion(ring,5,5));CHECK(!PtInRegion(ring,10,5));
    CHECK(GetRgnBox(ring,&bounds)==COMPLEXREGION);
    CHECK(bounds.left==0&&bounds.top==0&&bounds.right==10&&bounds.bottom==10);
    CHECK(CombineRgn(copy,ring,hole,RGN_OR)==SIMPLEREGION);CHECK(EqualRgn(copy,outer));
    CHECK(SelectObject(dc,bitmap)!=0);
    CHECK(SelectClipRgn(dc,ring)==COMPLEXREGION);
    CHECK(FillRect(dc,&fill,brush));
    CHECK(GetPixel(dc,0,0)==RGB(33,44,55));CHECK(GetPixel(dc,5,5)==RGB(0,0,0));
    CHECK(GetClipRgn(dc,copy)==1);CHECK(EqualRgn(copy,ring));
    CHECK(SelectClipRgn(dc,0)!=ERROR);
    CHECK(FillRect(dc,&fill,brush));CHECK(GetPixel(dc,5,5)==RGB(33,44,55));
    CHECK(PatBlt(dc,0,0,10,10,BLACKNESS));
    CHECK(IntersectClipRect(dc,2,2,8,8)==SIMPLEREGION);
    CHECK(ExcludeClipRect(dc,4,4,6,6)==COMPLEXREGION);
    CHECK(GetClipRgn(dc,copy)==1);
    CHECK(PtInRegion(copy,2,2) && !PtInRegion(copy,4,4) && PtInRegion(copy,6,4) && !PtInRegion(copy,8,2));
    CHECK(FillRect(dc,&fill,brush));
    CHECK(GetPixel(dc,2,2)==RGB(33,44,55));CHECK(GetPixel(dc,4,4)==0);CHECK(GetPixel(dc,8,2)==0);
    CHECK(GetClipBox(dc,&bounds)==COMPLEXREGION && bounds.left==2 && bounds.top==2 && bounds.right==8 && bounds.bottom==8);
    CHECK(IntersectClipRect(dc,3,3,3,8)==NULLREGION);
    CHECK(FillRect(dc,&fill,brush));CHECK(GetPixel(dc,0,0)==0);
    CHECK(SelectClipRgn(dc,0)==SIMPLEREGION);
    CHECK(ExcludeClipRect(dc,2,2,8,8)==COMPLEXREGION);
    CHECK(GetClipRgn(dc,copy)==1 && EqualRgn(copy,ring));
    CHECK(ExcludeClipRect(dc,0,0,10,10)==NULLREGION);
    CHECK(SelectClipRgn(dc,0)==SIMPLEREGION);
    CHECK(IntersectClipRect(dc,-5,-5,5,5)==SIMPLEREGION);
    CHECK(GetClipBox(dc,&bounds)==SIMPLEREGION && bounds.left==0 && bounds.top==0 && bounds.right==5 && bounds.bottom==5);
    CHECK(IntersectClipRect((HDC)0xdeadbeef,0,0,5,5)==ERROR);
    CHECK(ExcludeClipRect((HDC)0xdeadbeef,0,0,5,5)==ERROR);
    CHECK(GetClipBox(dc,&bounds)==SIMPLEREGION && bounds.right==5);
    CHECK(DeleteDC(dc));CHECK(DeleteObject(bitmap));CHECK(DeleteObject(brush));
    CHECK(DeleteObject(outer));CHECK(DeleteObject(hole));CHECK(DeleteObject(ring));CHECK(DeleteObject(copy));
    printf("WINCALLBACK %s regions\n",errors?"FAIL":"PASS");return errors?1:0;
}
