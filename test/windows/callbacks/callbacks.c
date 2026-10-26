#include <windows.h>
#include <stdio.h>
#include <string.h>

static const WCHAR wide_class[] = {'C','a','l','l','b','a','c','k','W',0};
static const WCHAR wide_title[] = {'W','i','d','e',0};
static const char ansi_class[] = "CallbackA";
static unsigned errors;
static unsigned failure_lines[64];
static HANDLE entered, done;
static HWND rejected;
static unsigned rejected_destroy, rejected_nc_destroy, rejected_create;
static DWORD timer_time;
static ATOM ansi_atom;

struct Creation {
    unsigned nc, create;
    int reject, nest, wait, wide;
    DWORD thread;
    HWND hwnd;
    const void *class_name;
};

#define CHECK(x) do { if (!(x)) { if (errors < 64) failure_lines[errors] = __LINE__; ++errors; } } while (0)

/* Callbacks also run on a raw CreateThread stack, without CRT TLS. */
#pragma off(check_stack)
static HWND make_window(struct Creation *c)
{
    if (c->wide)
        return CreateWindowExW(0, wide_class, wide_title, WS_POPUP,
                              11, 13, 71, 43, 0, 0, GetModuleHandleA(0), c);
    return CreateWindowExA(0, c->class_name, "Ansi", WS_POPUP,
                          11, 13, 71, 43, 0, 0, GetModuleHandleA(0), c);
}

static LRESULT CALLBACK wndproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    if (msg == WM_NCCREATE || msg == WM_CREATE) {
        CREATESTRUCTA *cs = (CREATESTRUCTA *)lp;
        struct Creation *c = (struct Creation *)cs->lpCreateParams;
        CHECK(c != NULL);
        if (!c) return -1;
        CHECK(cs->hInstance == GetModuleHandleA(0));
        CHECK(cs->hwndParent == 0 && cs->hMenu == 0);
        CHECK(cs->x == 11 && cs->y == 13 && cs->cx == 71 && cs->cy == 43);
        CHECK(cs->style == WS_POPUP && cs->dwExStyle == 0);
        CHECK((const void *)cs->lpszClass == c->class_name);
        CHECK(c->wide ? ((WCHAR *)cs->lpszName)[0] == 'W' : cs->lpszName[0] == 'A');
        CHECK(IsWindow(hwnd));
        CHECK(GetCurrentThreadId() == c->thread);
        c->hwnd = hwnd;
        if (msg == WM_NCCREATE) {
            CHECK(c->nc == 0 && c->create == 0);
            ++c->nc;
            if (c->reject == 1) { rejected = hwnd; return FALSE; }
            return c->wide ? DefWindowProcW(hwnd, msg, wp, lp)
                           : DefWindowProcA(hwnd, msg, wp, lp);
        }
        CHECK(c->nc == 1 && c->create == 0);
        ++c->create;
        if (c->reject == 2) { rejected = hwnd; ++rejected_create; return -1; }
        if (c->nest) {
            struct Creation inner = {0};
            HWND child;
            inner.class_name = ansi_class;
            inner.thread = GetCurrentThreadId();
            child = make_window(&inner);
            CHECK(child != 0 && inner.nc == 1 && inner.create == 1);
            CHECK(child != hwnd);
            CHECK(SendMessageA(child, WM_APP, 4, 0) == 104);
        }
        if (c->wait) {
            SetEvent(entered);
            CHECK(WaitForSingleObject(done, 2000) == WAIT_OBJECT_0);
            CHECK(GetCurrentThreadId() == c->thread);
            CHECK(cs->lpCreateParams == c && cs->cx == 71);
        }
        return 0;
    }
    if (msg == WM_APP) {
        if (wp) return SendMessageW(hwnd, WM_APP, wp - 1, lp) + 1;
        return 100;
    }
    if (msg == WM_DESTROY && hwnd == rejected) ++rejected_destroy;
    if (msg == WM_NCDESTROY && hwnd == rejected) ++rejected_nc_destroy;
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static DWORD WINAPI worker(void *unused)
{
    struct Creation c = {0};
    HWND hwnd;
    (void)unused;
    c.class_name = ansi_class;
    c.thread = GetCurrentThreadId();
    CHECK(WaitForSingleObject(entered, 2000) == WAIT_OBJECT_0);
    hwnd = make_window(&c);
    CHECK(hwnd != 0 && c.nc == 1 && c.create == 1);
    SetEvent(done);
    return 0;
}

static void CALLBACK timer(HWND hwnd, UINT msg, UINT id, DWORD time)
{
    CHECK(hwnd == 0 && msg == WM_TIMER && id == 7);
    timer_time = time;
}
#pragma on(check_stack)

static void rectangles(void)
{
    RECT a, b, r, empty;
    POINT point;
    CHECK(SetRect(&a, 1, 2, 11, 12));
    CHECK(SetRectEmpty(&empty) && IsRectEmpty(&empty));
    CHECK(CopyRect(&r, &a) && EqualRect(&r, &a));
    point.x = 1; point.y = 2;
    CHECK(PtInRect(&a, point));
    point.x = 11;
    CHECK(!PtInRect(&a, point));
    CHECK(OffsetRect(&r, -1, -2));
    CHECK(r.left == 0 && r.top == 0 && r.right == 10 && r.bottom == 10);
    CHECK(InflateRect(&r, 2, 3));
    CHECK(r.left == -2 && r.top == -3 && r.right == 12 && r.bottom == 13);
    SetRect(&b, 5, 6, 15, 16);
    CHECK(IntersectRect(&r, &a, &b));
    CHECK(r.left == 5 && r.top == 6 && r.right == 11 && r.bottom == 12);
    CHECK(UnionRect(&r, &r, &a)); /* destination aliases an operand */
    CHECK(EqualRect(&r, &a));
    CHECK(!IntersectRect(&r, &a, &empty) && EqualRect(&r, &empty));
    CHECK(UnionRect(&r, &empty, &a) && EqualRect(&r, &a));
    CHECK(!UnionRect(&r, &empty, &empty) && EqualRect(&r, &empty));
    SetRect(&b, 1, 2, 5, 12);
    CHECK(SubtractRect(&r, &a, &b));
    CHECK(r.left == 5 && r.top == 2 && r.right == 11 && r.bottom == 12);
    SetRect(&b, 4, 4, 6, 6); /* a hole keeps the original bounding box */
    CHECK(SubtractRect(&r, &a, &b) && EqualRect(&r, &a));
    CHECK(!SubtractRect(&r, &a, &a) && EqualRect(&r, &empty));
    SetRect(&b, 5, 6, 1, 2);
    CHECK(IsRectEmpty(&b));
}

int main(void)
{
    WNDCLASSW wcw;
    WNDCLASSEXA wca;
    struct Creation c;
    HWND hwnd;
    MSG msg;
    HANDLE thread;
    DWORD id;
    HMODULE user;
    HWND (WINAPI *create)(DWORD,LPCSTR,LPCSTR,DWORD,int,int,int,int,HWND,HMENU,HINSTANCE,LPVOID);
    rectangles();
    memset(&wcw, 0, sizeof(wcw));
    wcw.lpfnWndProc = wndproc;
    wcw.lpszClassName = wide_class;
    CHECK(RegisterClassW(&wcw) != 0);
    memset(&wca, 0, sizeof(wca));
    wca.cbSize = sizeof(wca);
    wca.lpfnWndProc = wndproc;
    wca.lpszClassName = ansi_class;
    ansi_atom = RegisterClassExA(&wca);
    CHECK(ansi_atom != 0);

    memset(&c, 0, sizeof(c));
    c.class_name = ansi_class;
    c.thread = GetCurrentThreadId();
    c.nest = 1;
    hwnd = make_window(&c);
    CHECK(hwnd != 0 && c.nc == 1 && c.create == 1);
    CHECK(SendMessageW(hwnd, WM_APP, 8, 0) == 108);
    CHECK(CallWindowProcA(wndproc, hwnd, WM_APP, 3, 0) == 103);
    CHECK(CallWindowProcW(wndproc, hwnd, WM_APP, 3, 0) == 103);
    memset(&msg, 0, sizeof(msg));
    msg.hwnd = hwnd;
    msg.message = WM_APP;
    msg.wParam = 5;
    CHECK(DispatchMessageA(&msg) == 105);
    CHECK(DispatchMessageW(&msg) == 105);
    /* Creation messages must not turn up later as queued messages. */
    CHECK(!PeekMessageA(&msg, 0, 0, 0, PM_REMOVE));

    memset(&c, 0, sizeof(c));
    c.class_name = wide_class;
    c.wide = 1;
    c.thread = GetCurrentThreadId();
    CHECK(make_window(&c) != 0 && c.nc == 1 && c.create == 1);

    memset(&c, 0, sizeof(c));
    c.class_name = (const void *)(unsigned)ansi_atom;
    c.thread = GetCurrentThreadId();
    user = GetModuleHandleA("USER32");
    create = (void *)GetProcAddress(user, "CreateWindowExA");
    CHECK(create != NULL);
    if (create) {
        hwnd = create(0, c.class_name, "Ansi", WS_POPUP,
                      11, 13, 71, 43, 0, 0, GetModuleHandleA(0), &c);
        CHECK(hwnd != 0 && c.nc == 1 && c.create == 1);
    }

    memset(&c, 0, sizeof(c));
    c.class_name = ansi_class;
    c.thread = GetCurrentThreadId();
    c.reject = 1;
    CHECK(make_window(&c) == 0 && c.nc == 1 && c.create == 0);
    CHECK(!IsWindow(rejected));
    CHECK(rejected_destroy == 0 && rejected_nc_destroy == 1);
    c.nc = 0;
    c.reject = 2;
    CHECK(make_window(&c) == 0 && c.nc == 1 && c.create == 1);
    CHECK(!IsWindow(rejected));
    CHECK(rejected_create == 1 && rejected_destroy == 1 && rejected_nc_destroy == 2);

    entered = CreateEventA(0, FALSE, FALSE, 0);
    done = CreateEventA(0, FALSE, FALSE, 0);
    CHECK(entered != 0 && done != 0);
    thread = CreateThread(0, 0, worker, 0, 0, &id);
    CHECK(thread != 0);
    memset(&c, 0, sizeof(c));
    c.class_name = ansi_class;
    c.thread = GetCurrentThreadId();
    c.wait = 1;
    CHECK(make_window(&c) != 0 && c.nc == 1 && c.create == 1);
    CHECK(WaitForSingleObject(thread, 2000) == WAIT_OBJECT_0);
    CloseHandle(thread);
    CloseHandle(entered);
    CloseHandle(done);

    memset(&msg, 0, sizeof(msg));
    msg.message = WM_TIMER;
    msg.wParam = 7;
    msg.lParam = (LPARAM)timer;
    msg.time = 1234;
    DispatchMessageW(&msg);
    CHECK(timer_time == 1234);
    if (errors) { unsigned i; for(i=0;i<errors && i<64;i++) printf("failed line %u\n",failure_lines[i]); printf("WINCALLBACK FAIL %u\n", errors); return 1; }
    puts("WINCALLBACK PASS");
    return 0;
}
