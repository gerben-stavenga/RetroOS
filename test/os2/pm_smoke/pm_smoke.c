typedef unsigned long ULONG;
typedef long LONG;
typedef ULONG HAB;
typedef ULONG HMQ;
typedef ULONG HWND;
typedef ULONG HPS;
typedef ULONG MPARAM;
typedef int BOOL;

typedef struct {
    LONG xLeft;
    LONG yBottom;
    LONG xRight;
    LONG yTop;
} RECTL;

typedef struct {
    HWND hwnd;
    ULONG msg;
    MPARAM mp1;
    MPARAM mp2;
    ULONG time;
    LONG x;
    LONG y;
} QMSG;

extern HAB __syscall WinInitialize(ULONG);
extern HMQ __syscall WinCreateMsgQueue(HAB, LONG);
extern HWND __syscall WinCreateWindow(HWND, const char *, const char *, ULONG,
    LONG, LONG, LONG, LONG, HWND, HWND, ULONG, void *, void *);
extern BOOL __syscall WinShowWindow(HWND, BOOL);
extern HPS __syscall WinGetPS(HWND);
extern BOOL __syscall WinReleasePS(HPS);
extern BOOL __syscall WinFillRect(HPS, const RECTL *, LONG);
extern BOOL __syscall WinPostQueueMsg(HMQ, ULONG, MPARAM, MPARAM);
extern BOOL __syscall WinGetMsg(HAB, QMSG *, HWND, ULONG, ULONG);
extern ULONG __syscall WinDispatchMsg(HAB, const QMSG *);
extern BOOL __syscall WinDestroyWindow(HWND);
extern BOOL __syscall WinDestroyMsgQueue(HMQ);
extern BOOL __syscall WinTerminate(HAB);
extern void __syscall DosExit(ULONG, ULONG);

enum { HWND_DESKTOP = 1, HWND_TOP = 3, WS_VISIBLE = 0x80000000UL };
enum { WM_USER = 0x1000 };

void _start(void)
{
    HAB hab = WinInitialize(0);
    HMQ hmq = WinCreateMsgQueue(hab, 0);
    HWND window = WinCreateWindow(HWND_DESKTOP, "#5", "RetroOS Presentation Manager",
        WS_VISIBLE, 0, 0, 360, 220, HWND_DESKTOP, HWND_TOP, 1, 0, 0);
    HPS hps;
    RECTL whole = { 0, 0, 360, 220 };
    RECTL panel = { 24, 24, 336, 196 };
    QMSG message;
    ULONG i;

    WinShowWindow(window, 1);
    hps = WinGetPS(window);
    WinFillRect(hps, &whole, 0x00d8d0c8L);
    /* Let the compositor publish this first update before drawing again. */
    for (i = 0; i != 10000; ++i) {
        WinGetMsg(hab, &message, 0, 0, 0);
        WinDispatchMsg(hab, &message);
    }
    WinFillRect(hps, &panel, 0x004878b8L);
    WinReleasePS(hps);

    /* Exercise a real PM queue before terminating this finite smoke test. */
    WinPostQueueMsg(hmq, WM_USER, 0, 0);
    while (WinGetMsg(hab, &message, 0, 0, 0))
        WinDispatchMsg(hab, &message);

    WinDestroyWindow(window);
    WinDestroyMsgQueue(hmq);
    WinTerminate(hab);
    DosExit(1, 0);
}
