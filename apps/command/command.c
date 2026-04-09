/* COMMAND.COM — minimal shell for RetroOS
 *
 * Compiled inside RetroOS by BCC at boot.
 *
 * All parsing and dispatching lives in the kernel's synth INT 31h handler:
 *   AH=01h SYNTH_FORK_EXEC_WAIT: reads caller's own PSP cmdline, strips "/C",
 *          fork+execs the named program, blocks until child exits or F11.
 *          Out: CF=0, BX=child_pid, AX=0 exited | AX=1 decoupled
 *               CF=1, AX=errno on failure.
 *   AH=00h SYNTH_VGA_TAKE: adopt target pid's final screen (BX=child_pid).
 */

#include <dos.h>

int main(void)
{
    union REGS r;
    int child_pid;

    /* AH=01h SYNTH_FORK_EXEC_WAIT */
    r.h.ah = 0x01;
    int86(0x31, &r, &r);

    if (r.x.cflag) {
        /* error */
        r.x.ax = 0x4C01;
        int86(0x21, &r, &r);
    }

    child_pid = r.x.bx;

    if (r.x.ax == 0) {
        /* child exited normally — adopt its screen */
        r.x.ax = 0x0000;
        r.x.bx = child_pid;
        int86(0x31, &r, &r);
    }
    /* else: backgrounded (F11 decoupled), keep our own screen */

    r.x.ax = 0x4C00;
    int86(0x21, &r, &r);
    return 0;
}
