/* COMMAND.COM -- minimal launcher for RetroOS.
 *
 * Splits the launch into fork_exec (non-blocking) + waitpid poll, so the
 * backgrounding policy lives here, not in the kernel.
 *
 *   INT 31h AH=01h SYNTH_FORK_EXEC   -- read PSP cmdline, fork+exec named
 *                                      program. Out: CF=0 AX=0 BX=child_pid;
 *                                      CF=1 AX=errno on error.
 *   INT 31h AH=04h SYNTH_WAITPID     -- non-blocking probe of child status
 *                                      (BX=pid). Out: CF=0 AX=0 -> exited
 *                                      (status via 4Dh); CF=0 AX=1 -> still
 *                                      alive; CF=1 AX=errno.
 *   INT 31h AH=00h SYNTH_VGA_TAKE    -- adopt child's farewell screen
 *                                      (BX=child_pid).
 *   INT 31h AH=02/03h TRACE_ON/OFF   -- bracket the launch in the trace log.
 *
 * The focused thread runs continuously, so the AH=04 loop is just a status
 * query -- no kernel-side blocking. While focus is on us we also poll the
 * keyboard via INT 21h AH=0B (status) + AH=07 (read no-echo no-Ctrl-C):
 * Ctrl-Z (0x1A) backgrounds and returns to whoever exec'd us.
 *
 * Build: see BUILD.bazel -- DOSBox-X + Borland C++ 3.1, tiny model -> .COM.
 */

#include <dos.h>

static union REGS r;

static void trace(int on) {
    r.h.ah = on ? 0x02 : 0x03;
    int86(0x31, &r, &r);
}

static void print_str(char *s) {
    r.h.ah = 0x09;
    r.x.dx = (unsigned)s;
    int86(0x21, &r, &r);
}

static void exit_dos(unsigned char code) {
    r.h.ah = 0x4C;
    r.h.al = code;
    int86(0x21, &r, &r);
}

int main(void) {
    int child_pid;

    trace(1);

    /* fork+exec */
    r.h.ah = 0x01;
    int86(0x31, &r, &r);
    if (r.x.cflag) goto err;
    child_pid = r.x.bx;

    for (;;) {
        /* poll child status */
        r.h.ah = 0x04;
        r.x.bx = child_pid;
        int86(0x31, &r, &r);
        if (r.x.cflag) goto err;
        if (r.x.ax == 0) break;  /* child exited */

        /* drain keystrokes without blocking; Ctrl-Z = background */
        for (;;) {
            r.h.ah = 0x0B;       /* get stdin status */
            int86(0x21, &r, &r);
            if (r.h.al == 0) break;  /* no key */
            r.h.ah = 0x07;       /* read raw, no echo */
            int86(0x21, &r, &r);
            if (r.h.al == 0x1A) {
                trace(0);
                print_str("[Backgrounded]\r\n$");
                exit_dos(0);
            }
        }
    }

    trace(0);
    /* adopt child's final screen */
    r.h.ah = 0x00;
    r.x.bx = child_pid;
    int86(0x31, &r, &r);
    /* forward child's exit code */
    r.h.ah = 0x4D;
    int86(0x21, &r, &r);
    exit_dos(r.h.al);

err:
    trace(0);
    print_str("Bad command or file name\r\n$");
    exit_dos(1);
    return 0;  /* unreachable */
}
