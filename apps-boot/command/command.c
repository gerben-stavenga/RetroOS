/* COMMAND.COM -- minimal DOS shell launcher for RetroOS.
 *
 * Invoked one-shot as `COMMAND.COM /C cmdline` (or `COMMAND.COM cmdline`).
 * Reads its arguments through ANSI `int main(int argc, char *argv[])` (the
 * Borland C startup parses the PSP tail into argv); then either:
 *   - runs a built-in (REM/ECHO/CD/CLS/TYPE/PAUSE/TRACE/EXIT),
 *   - interprets a .BAT file line by line,
 *   - or fork+execs an external program and waits for it.
 *
 * The kernel-side INT 31h API is now layer-clean:
 *   AH=01h SYNTH_FORK_EXEC   DS:DX -> ASCIIZ program name
 *                            ES:BX -> ASCIIZ args (use "" for none)
 *                            -> CF=0 AX=0 BX=child_pid; CF=1 AX=errno
 *   AH=04h SYNTH_WAITPID     BX=pid -> CF=0 AX=0 exited / AX=1 alive
 *                            (peek only; slot stays Zombie until AH=00).
 *   AH=00h SYNTH_VGA_TAKE    BX=pid -> adopt the zombie child's farewell
 *                            screen and reap the slot.
 *   AH=02/03h TRACE_ON/OFF
 *
 * No shell logic in the kernel: filename parsing, .BAT, /C, and built-in
 * dispatch all live here.
 *
 * Build: tiny model .COM via Borland C++ 3.1 (DS=ES=CS=SS=PSP segment).
 */

#include <assert.h>
#include <dos.h>
#include <dir.h>
#include <conio.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

static union REGS r;
static struct SREGS s;
static int echo_on = 1;
static int should_exit = 0;     /* set by EXIT builtin to break out of BAT */
static const char empty_str[] = "";

/* ----- thin INT wrappers ----- */

static void trace(int on) {
    r.h.ah = (unsigned char)(on ? 0x02 : 0x03);
    int86(0x31, &r, &r);
}

/* ----- per-program launch overrides (LOADFIX.CFG) -----
 *
 * Two kinds of override are wired through here:
 *
 *   loadfix: EXEPACK-compressed binaries (Borland CHESS, plenty of
 *     early-90s tools) have a relocator bug that crashes when loaded
 *     below segment 0x1000. Real DOS shipped LOADFIX.COM which allocated
 *     ~64 KB low, pushing the program above 0x1000. Implemented here as
 *     a trampoline: parent forks COMMAND.COM with "/L <name> [args]";
 *     the child takes the /L branch and EXECs the program in-process via
 *     INT 21h AH=4B AL=00. The trampoline itself is the push-up -- our
 *     COMMAND.COM is a tiny-model .COM and claims a full 64 KB block,
 *     exactly the shift real LOADFIX provided.
 *
 *   dos32a:  DOS/4GW-bound games that don't run cleanly under our DPMI
 *     host. Wrapped by spawning C:\DOS32A.EXE with "<prog> [args]" as
 *     command tail; DOS/32A is a near-drop-in DOS/4GW replacement that
 *     follows DPMI 0.9 more strictly.
 *
 * LOADFIX.CFG format: BASENAME [keyword [keyword...]]. Keywords:
 *   loadfix (default if none), dos32a. Combinable.
 *
 * The kernel knows nothing about either override -- both are implemented
 * entirely in this file. */

#define LF_MAX_NAMES 32
#define LF_NAME_LEN  16
#define LF_F_LOADFIX 0x01
#define LF_F_DOS32A  0x02

static char          loadfix_names[LF_MAX_NAMES][LF_NAME_LEN];
static unsigned char loadfix_flags[LF_MAX_NAMES];
static int           loadfix_count = 0;

/* Last component of a DOS path: skip past any '\\', '/', or ':'. */
static const char *basename_of(const char *path) {
    const char *p = path;
    const char *q;
    while ((q = strpbrk(p, "\\/:")) != 0) p = q + 1;
    return p;
}

static int has_ext(const char *name, const char *ext) {
    const char *dot = strrchr(name, '.');
    return dot && stricmp(dot, ext) == 0;
}

/* Parse a flag token; 0 = unrecognised. */
static unsigned char parse_flag(const char *tok) {
    if (stricmp(tok, "loadfix") == 0) return LF_F_LOADFIX;
    if (stricmp(tok, "dos32a")  == 0) return LF_F_DOS32A;
    return 0;
}

static void load_loadfix_cfg(void) {
    FILE *f;
    char line[80];
    f = fopen("C:\\LOADFIX.CFG", "r");
    if (!f) return;
    while (loadfix_count < LF_MAX_NAMES && fgets(line, sizeof(line), f) != 0) {
        char *p = line + strspn(line, " \t");
        char *name, *tok;
        unsigned char flags = 0;
        if (*p == 0 || *p == ';' || *p == '#' || *p == '\r' || *p == '\n') continue;
        /* Strip CR/LF terminator but leave inline whitespace for tokenising. */
        p[strcspn(p, "\r\n")] = 0;
        name = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (*p) { *p++ = 0; }
        if (strlen(name) == 0 || strlen(name) >= LF_NAME_LEN) continue;
        for (;;) {
            p += strspn(p, " \t");
            if (*p == 0) break;
            tok = p;
            while (*p && *p != ' ' && *p != '\t') p++;
            if (*p) *p++ = 0;
            flags |= parse_flag(tok);
        }
        if (flags == 0) flags = LF_F_LOADFIX;   /* legacy default */
        strcpy(loadfix_names[loadfix_count], name);
        loadfix_flags[loadfix_count] = flags;
        loadfix_count++;
    }
    fclose(f);
}

static unsigned char lookup_flags(const char *name) {
    const char *base = basename_of(name);
    int i;
    for (i = 0; i < loadfix_count; i++) {
        if (stricmp(base, loadfix_names[i]) == 0) return loadfix_flags[i];
    }
    return 0;
}

/* ----- program resolution -----
 *
 * Real DOS keeps INT 21h AH=4B raw: it takes a fully-qualified filename
 * and that's it. PATH search and extension probing live in COMMAND.COM,
 * and we do the same -- the kernel never sees a bare "command", only
 * "C:\\COMMAND.COM" once we've resolved it. */

static int file_exists(const char *p) {
    FILE *f = fopen(p, "rb");
    if (!f) return 0;
    fclose(f);
    return 1;
}

/* Probe `prefix` + `name`, optionally trying .COM/.EXE/.BAT if the name
 * has no extension. Writes resolved path to `out` and returns 1 on hit. */
static int try_resolve(const char *prefix, const char *name, char *out) {
    static const char *exts[] = { ".COM", ".EXE", ".BAT" };
    int i;
    if (strchr(name, '.')) {
        sprintf(out, "%s%s", prefix, name);
        return file_exists(out);
    }
    for (i = 0; i < 3; i++) {
        sprintf(out, "%s%s%s", prefix, name, exts[i]);
        if (file_exists(out)) return 1;
    }
    return 0;
}

/* Resolve a program name like real COMMAND.COM:
 *   - drive/dir-qualified: take as-is, just probe extensions.
 *   - bare: probe cwd, then walk PATH dirs.
 * .COM beats .EXE beats .BAT. Returns 1 on hit, 0 on "not found". */
static int resolve_program(const char *name, char *out) {
    char *path_env, *p;
    char dir[80];
    int qualified = strpbrk(name, "\\/") != 0
                 || (name[0] && name[1] == ':');

    if (qualified) return try_resolve("", name, out);
    if (try_resolve("", name, out)) return 1;

    path_env = getenv("PATH");
    if (!path_env) return 0;
    p = path_env;
    while (*p) {
        size_t dlen = strcspn(p, ";");
        if (dlen > 0 && dlen < sizeof(dir) - 1) {
            memcpy(dir, p, dlen);
            dir[dlen] = 0;
            if (!strchr("\\/:", dir[dlen-1])) strcat(dir, "\\");
            if (try_resolve(dir, name, out)) return 1;
        }
        p += dlen;
        if (*p == ';') p++;
    }
    return 0;
}

static char *skipws(char *p) {
    while (*p == ' ' || *p == '\t') p++;
    return p;
}

#define MAX_ARGV 16

/* Tokenize `line` in place: NUL-terminate each whitespace-delimited token
 * and write pointers into argv[]. Returns argc, capped at max-1 to leave
 * room for a NULL sentinel that we don't actually write (callers use argc).
 * Modifies `line` (writes NULs over separators). */
static int tokenize(char *line, char **argv, int max) {
    int n = 0;
    char *p = skipws(line);
    while (*p && n < max) {
        argv[n++] = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (*p) { *p++ = 0; p = skipws(p); }
    }
    return n;
}

/* Join argv[start..argc-1] into dst as a single space-separated string,
 * NUL-terminated. Used to rebuild the cmdline tail to hand off to a child
 * (the kernel writes the tail verbatim to the child's PSP[0x80]). */
static void join_args(char *dst, int max, char **argv, int start, int argc) {
    int len = 0;
    int i, n;
    for (i = start; i < argc; i++) {
        n = (int)strlen(argv[i]);
        if (len + (i > start ? 1 : 0) + n + 1 > max) break;
        if (i > start) dst[len++] = ' ';
        memcpy(dst + len, argv[i], (size_t)n);
        len += n;
    }
    dst[len] = 0;
}

/* ----- kernel synth syscalls ----- */

static unsigned int get_child_exit_status(void);

static int synth_fork_exec(const char *name, const char *args) {
    /* Take far pointers so the segments come from the pointers
     * themselves rather than whatever ES happens to be at the
     * call site (HW-IRQ delivery clears ES). The tiny-model
     * `const char *` arguments auto-convert to `const char far *`
     * with DS as the segment. */
    const char far *fname = name;
    const char far *fargs = args ? args : empty_str;
    r.h.ah = 0x01;
    r.x.dx = FP_OFF(fname);
    r.x.bx = FP_OFF(fargs);
    s.ds   = FP_SEG(fname);
    s.es   = FP_SEG(fargs);
    int86x(0x31, &r, &r, &s);
    if (r.x.cflag) return -1;
    return (int)r.x.bx;
}

/* In-process EXEC via INT 21h AH=4Bh AL=00h. Child loads in our address
 * space at our heap_seg, runs, exits, control returns here. Used by the
 * LOADFIX trampoline path (see /L handling below): we alloc a dummy
 * low block first, then EXEC, so the child's PSP lands above segment
 * 0x1000 -- far enough to dodge EXEPACK's load-low relocation overflow. */
static int dos_exec_inplace(const char *name, const char *args) {
    static char cmdtail[130];
    static struct {
        unsigned env_seg;
        unsigned cmdline_off;
        unsigned cmdline_seg;
        unsigned long fcb1;
        unsigned long fcb2;
    } pb;
    const char far *fname    = name;
    const char far *fcmdtail = cmdtail;
    void far       *fpb      = &pb;
    int alen = (int)strlen(args);
    if (alen > 127) alen = 127;
    cmdtail[0] = (unsigned char)alen;
    memcpy(cmdtail + 1, args, alen);
    cmdtail[1 + alen] = 0x0D;

    pb.env_seg     = 0;             /* 0 = inherit our env */
    pb.cmdline_off = FP_OFF(fcmdtail);
    pb.cmdline_seg = FP_SEG(fcmdtail);
    pb.fcb1        = 0;
    pb.fcb2        = 0;

    r.x.ax = 0x4B00;
    r.x.dx = FP_OFF(fname);
    r.x.bx = FP_OFF(fpb);
    s.ds   = FP_SEG(fname);
    s.es   = FP_SEG(fpb);
    int86x(0x21, &r, &r, &s);
    if (r.x.cflag) return 255;
    return (int)(get_child_exit_status() & 0xFF);
}

static int synth_waitpid(int pid) {
    r.h.ah = 0x04;
    r.x.bx = (unsigned)pid;
    int86(0x31, &r, &r);
    if (r.x.cflag) return -1;
    return (int)r.x.ax;   /* 0 = exited, 1 = still alive */
}

static void vga_take(int pid) {
    r.h.ah = 0x00;
    r.x.bx = (unsigned)pid;
    int86(0x31, &r, &r);
}

/* INT 31h AH=06h: peek the zombie child's VGA mode without taking it.
 * Returns 0 = text, 1 = graphics, -1 = error. Used to skip vga_take when
 * the child exited in graphics mode (the leftover planar framebuffer
 * doesn't compose with a fresh text-mode redraw by the next program). */
static int synth_vga_is_graphics(int pid) {
    r.h.ah = 0x06;
    r.x.bx = (unsigned)pid;
    int86(0x31, &r, &r);
    if (r.x.cflag) return -1;
    return (int)r.h.al;
}

/* INT 31h AH=05h: reap a zombie child without touching VGA. Use this
 * when the child terminated abnormally (high byte of AH=4Dh status =
 * 0x02) and its VGA state is suspect. */
static void synth_reap(int pid) {
    r.h.ah = 0x05;
    r.x.bx = (unsigned)pid;
    int86(0x31, &r, &r);
}

/* INT 21h AH=4Dh: full child exit status word. High byte = termination
 * type (00=normal, 01=Ctrl-Break, 02=fault, 03=TSR), low byte = AL/vector. */
static unsigned int get_child_exit_status(void) {
    r.h.ah = 0x4D;
    int86(0x21, &r, &r);
    return (unsigned int)r.x.ax;
}

/* Fork-exec a child and wait for it. argv[0] = program path,
 * argv[1..argc-1] = args. The args are joined into the cmdline tail
 * right here at the synth call boundary so callers stay tokenised.
 * `poll_kbd` enables the Ctrl-Z = background gesture used by the
 * interactive launcher path; batch lines pass 0. */
static int run_external_raw(char **argv, int argc, int poll_kbd) {
    char tail[128];
    int pid, rc;
    join_args(tail, sizeof(tail), argv, 1, argc);
    pid = synth_fork_exec(argv[0], tail);
    if (pid < 0) {
        printf("Bad command or file name: '%s'\r\n", argv[0]);
        return 255;
    }
    for (;;) {
        rc = synth_waitpid(pid);
        if (rc < 0) return 255;          /* no such child / EINVAL */
        if (rc == 0) break;              /* exited */
        if (poll_kbd) {
            while (kbhit()) {
                if (getch() == 0x1A) {
                    puts("[Backgrounded]");
                    return 0;
                }
            }
        }
    }
    {
        unsigned int status = get_child_exit_status();
        unsigned char term_type = (unsigned char)(status >> 8);
        unsigned char exit_al   = (unsigned char)(status & 0xFF);
        if (term_type == 0x02) {
            /* Critical error / fault: skip vga_take (the dying child's
             * VGA is suspect), just reap. Our own VGA context (already
             * text mode from when we were suspended) gets restored by
             * the kernel's materialize on the next thread-switch. */
            printf("Aborted (critical error)\r\n");
            synth_reap(pid);
            printf("Reaped child %d with exit status %02Xh\r\n", pid, exit_al);
            return 1;
        }
        /* Only adopt the farewell screen if the child exited in text
         * mode. Graphics-mode leftovers (e.g. Alley Cat aborted with
         * Ctrl-Y) don't compose with the next program's text redraw —
         * the planar framebuffer interprets text bytes as pixels and
         * the user sees tiled garbage. */
        if (synth_vga_is_graphics(pid) == 0) {
            vga_take(pid);
        } else {
            synth_reap(pid);
        }
        return (int)exit_al;
    }
}

/* Dispatch an external program. argv[prog_idx] is the program to run;
 * argv[prog_idx-1] and argv[prog_idx-2] are scratch slots the caller has
 * reserved for trampoline prefixes (this function may mutate them, plus
 * argv[prog_idx] which gets replaced with the resolved full path).
 *
 * Caller layouts:
 *   - main(): argv[0]="COMMAND.COM" argv[1]="/C" argv[2..]=prog,args
 *             -> prog_idx=2, both scratch slots present.
 *   - run_bat_line(): tokenises into argv[2..], leaves argv[0..1] empty
 *                     -> prog_idx=2, both scratch slots present.
 *
 * No copy: the trampoline-prefix injection writes back into the caller's
 * own argv slots and we hand a pointer slice to run_external_raw. */
static int dispatch_external(char **argv, int prog_idx, int argc, int poll_kbd) {
    char resolved[80];
    unsigned char flags;
    if (prog_idx >= argc) return 0;
    assert(prog_idx >= 2);
    if (!resolve_program(argv[prog_idx], resolved)) {
        printf("Bad command or file name: '%s'\r\n", argv[prog_idx]);
        return 255;
    }
    if (has_ext(resolved, ".BAT")) return run_bat_file(resolved);
    argv[prog_idx] = resolved;
    flags = lookup_flags(resolved);
    if (flags & LF_F_DOS32A) {
        /* Spawn DOS/32A.EXE with prog + args as its tail. DOS/32A loads
         * the target itself and provides a stricter DPMI 0.9 environment
         * than DOS/4GW's embedded one.
         *
         * Pass the full drive-qualified path: DOS/32A relays it as
         * argv[0] to the wrapped program, and DOS/4GW games (Dark
         * Forces, Hexen, Duke3D) parse argv[0] to find their install
         * dir. With just a basename they fall back to drive root and
         * fail to find data files (LOCAL.MSG, *.GOB, ...). */
        static char fullpath[80];
        if (!strchr(resolved, '\\') && !strchr(resolved, ':')) {
            char dir[80];
            if (getcwd(dir, sizeof(dir)) != 0) {
                /* getcwd returns "DRIVE:\path" or "DRIVE:\" at root. */
                size_t dlen = strlen(dir);
                int needs_sep = dlen == 0 || dir[dlen - 1] != '\\';
                sprintf(fullpath, "%s%s%s", dir, needs_sep ? "\\" : "", resolved);
                argv[prog_idx] = fullpath;
            }
        }
        prog_idx--;   /* shift back to overwrite caller's argv[prog_idx-1] with DOS/32A.EXE */
        argv[prog_idx] = "C:\\DOS32A.EXE";
    } else if (flags & LF_F_LOADFIX) {
        /* Re-fork COMMAND.COM with cmdline "/L prog [args]". The trampoline
         * child takes the /L branch in main() and EXECs the program
         * in-process -- its PSP lands above seg 0x1000, dodging EXEPACK's
         * load-low bug. */
         prog_idx -= 2;   /* shift back to overwrite caller's argv[prog_idx-2] with COMMAND.COM */
        argv[prog_idx] = "C:\\COMMAND.COM";
        argv[prog_idx + 1] = "/L";
    }
    return run_external_raw(&argv[prog_idx], argc - prog_idx, poll_kbd);
}

/* ----- built-ins -----
 *
 * All builtins take (argv, argc) where argv[0] is the command name (so
 * argv[1..argc-1] are the arguments). Mirrors the int main() convention,
 * keeps tokenisation in a single place (the BAT-line / cmdline parser). */

/* Run the command at argv[prog_idx] with arguments at argv[prog_idx+1..argc-1].
 * Built-ins (REM/ECHO/CD/CLS/TYPE/PAUSE/TRACE/EXIT) are matched first and
 * handled inline; if none match, dispatch_external takes over at the tail.
 * argv[prog_idx-1] and argv[prog_idx-2] (when prog_idx >= 1 / >= 2) must be
 * caller-reserved scratch slots that dispatch_external may overwrite for
 * trampoline-prefix injection. Returns the command's exit code. */
static int run_command(char **argv, int prog_idx, int argc, int poll_kbd) {
    const char *name;
    int args = prog_idx + 1;            /* index of first argument token */
    int nargs = argc - args;            /* number of argument tokens */

    if (prog_idx >= argc) return 0;
    name = argv[prog_idx];

    if (stricmp(name, "REM") == 0) return 0;
    if (stricmp(name, "ECHO") == 0) {
        char joined[128];
        if (nargs <= 0) {
            puts(echo_on ? "ECHO is on" : "ECHO is off");
        } else if (nargs == 1 && stricmp(argv[args], "ON")  == 0) {
            echo_on = 1;
        } else if (nargs == 1 && stricmp(argv[args], "OFF") == 0) {
            echo_on = 0;
        } else {
            join_args(joined, sizeof(joined), argv, args, argc);
            puts(joined);
        }
        return 0;
    }
    if (stricmp(name, "CD") == 0 || stricmp(name, "CHDIR") == 0) {
        char path[MAXPATH];
        if (nargs <= 0) {
            if (getcwd(path, sizeof(path)) == 0) { puts("getcwd failed"); return 1; }
            puts(path);
            return 0;
        }
        if (chdir(argv[args]) != 0) { puts("Invalid directory"); return 1; }
        return 0;
    }
    if (stricmp(name, "CLS") == 0) {
        clrscr();
        return 0;
    }
    if (stricmp(name, "TYPE") == 0) {
        char buf[256];
        FILE *f;
        int n;
        if (nargs <= 0) { puts("Required parameter missing"); return 1; }
        f = fopen(argv[args], "rb");
        if (!f) { puts("File not found"); return 1; }
        while ((n = (int)fread(buf, 1, sizeof(buf), f)) > 0) {
            fwrite(buf, 1, (size_t)n, stdout);
        }
        fclose(f);
        return 0;
    }
    if (stricmp(name, "PAUSE") == 0) {
        printf("Press any key to continue . . .\n");
        getch();
        return 0;
    }
    if (stricmp(name, "TRACE") == 0) {
        /* Recurse on the inner command at args (prog_idx + 1). The original
         * scratch slots before prog_idx stay available, and argv[prog_idx]
         * ("TRACE", already consumed) becomes an additional reusable slot,
         * so the inner program sees at least as many scratch slots as the
         * outer dispatch -- no degradation for LOADFIX/DOS32A wrapping. */
        int rc;
        if (nargs <= 0) {
            printf("Usage: trace <program> [args]\r\n");
            return 1;
        }
        trace(1);
        rc = run_command(argv, args, argc, poll_kbd);
        trace(0);
        return rc;
    }
    if (stricmp(name, "EXIT") == 0) {
        should_exit = 1;
        return (nargs > 0) ? atoi(argv[args]) : 0;
    }

    /* Tail: not a built-in -- spawn as external program. */
    return dispatch_external(argv, prog_idx, argc, poll_kbd);
}

/* ----- batch interpreter ----- */

/* Execute one line of a .BAT file (no trailing CR/LF, NUL-terminated).
 * Tokenises the line into argv[2..] (leaving argv[0..1] as scratch slots
 * for trampoline-prefix injection in dispatch_external), then dispatches. */
static int run_bat_line(char *line) {
    char *argv[MAX_ARGV];
    char *p = skipws(line);
    int suppress_echo = 0;
    int n;

    if (*p == 0)   return 0;   /* blank */
    if (*p == ':') return 0;   /* label */
    if (*p == '@') { suppress_echo = 1; p++; p = skipws(p); }

    if (echo_on && !suppress_echo) puts(p);

    n = tokenize(p, &argv[2], MAX_ARGV - 2);
    if (n == 0) return 0;

    return run_command(argv, 2, n + 2, 0);
}

static int run_bat_file(const char *path) {
    FILE *f;
    char line[256];
    int last = 0;
    f = fopen(path, "r");
    if (f == 0) { puts("Cannot open batch file"); return 1; }
    while (fgets(line, sizeof(line), f) != 0) {
        int n = (int)strlen(line);
        while (n > 0 && (line[n-1] == '\r' || line[n-1] == '\n')) line[--n] = 0;
        last = run_bat_line(line);
        if (should_exit) break;
    }
    fclose(f);
    return last;
}

/* ----- entry point ----- */

/* Returns 1 iff argv[i] is exactly "/<flag>" or "/<flag>" with case-insensitive
 * match on a single ASCII letter. Used for /C and /L parsing. */
static int is_flag(const char *arg, char letter) {
    return arg[0] == '/' &&
           (arg[1] == letter || arg[1] == (letter ^ 0x20)) &&
           arg[2] == 0;
}

int main(int argc, char *argv[]) {
    load_loadfix_cfg();

    /* Invocation contract: COMMAND.COM is always called as
     *   COMMAND.COM /L prog [args]   (LOADFIX trampoline)
     * or
     *   COMMAND.COM /C prog [args]   (one-shot run)
     *
     * Mandating one of /L or /C guarantees argv[0] ("COMMAND.COM") and
     * argv[1] (the flag) are both writable scratch slots in front of
     * argv[2] (the program) -- exactly what dispatch_external needs to
     * inject trampoline prefixes in place without an extra buffer. */
    if (argc < 2 || (!is_flag(argv[1], 'L') && !is_flag(argv[1], 'C'))) {
        printf("Usage: COMMAND.COM /C cmdline   (or /L for LOADFIX)\r\n");
        return 1;
    }

    /* /L progname [args] -- LOADFIX trampoline entry. The interactive
     * COMMAND.COM forks us with this when it sees a name in loadfix.cfg;
     * we EXEC the program in-process so its PSP lands above segment
     * 0x1000 (dodging EXEPACK's load-low bug). */
    if (is_flag(argv[1], 'L')) {
        char tail[128];
        if (argc < 3) {
            printf("/L requires program name\r\n");
            return 1;
        }
        join_args(tail, sizeof(tail), argv, 3, argc);
        return dos_exec_inplace(argv[2], tail);
    }

    /* /C path: argv[2] is the program/builtin, argv[3..] are its args.
     * argv[0] and argv[1] are guaranteed scratch for trampoline prefixes.
     * Interactive launcher mode -- poll kbd so Ctrl-Z backgrounds. */
    return run_command(argv, 2, argc, 1);
}
