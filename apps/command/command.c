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

/* Split off the first whitespace-delimited token in `line` in place:
 * returns a pointer to the token (NUL-terminated), and *rest_out points
 * past the following whitespace at the start of the remainder. */
static char *split_first(char *line, char **rest_out) {
    char *tok = skipws(line);
    char *p = tok;
    while (*p && *p != ' ' && *p != '\t') p++;
    if (*p) { *p++ = 0; p = skipws(p); }
    *rest_out = p;
    return tok;
}

/* Join argv[start..argc-1] into dst as a single space-separated string,
 * NUL-terminated. Used to rebuild the cmdline tail to hand off to a child
 * (the kernel writes the tail verbatim to the child's PSP[0x80]). */
static void join_args(char *dst, int max, char *argv[], int start, int argc) {
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
    int alen = (int)strlen(args);
    if (alen > 127) alen = 127;
    cmdtail[0] = (unsigned char)alen;
    memcpy(cmdtail + 1, args, alen);
    cmdtail[1 + alen] = 0x0D;

    segread(&s);
    pb.env_seg     = 0;             /* 0 = inherit our env */
    pb.cmdline_off = (unsigned)cmdtail;
    pb.cmdline_seg = s.ds;
    pb.fcb1        = 0;
    pb.fcb2        = 0;

    r.x.ax = 0x4B00;
    r.x.dx = (unsigned)name;
    r.x.bx = (unsigned)&pb;
    s.es = s.ds;
    int86x(0x21, &r, &r, &s);
    if (r.x.cflag) return 255;
    return (int)(get_child_exit_status() & 0xFF);
}

/* /L handler: just EXEC in-process. Our trampoline COMMAND.COM is
 * itself a full 64 KB .COM block, so the EXEC'd child already lands
 * with its PSP well above segment 0x1000 -- no extra dummy alloc is
 * needed. (Real DOS LOADFIX existed because its COMMAND.COM resident
 * was only a few KB; ours isn't.) Adding a dummy here would actually
 * break the load: CHESS.EXE asks for ~440 KB minalloc and any extra
 * low alloc pushes us past the 640 KB conventional ceiling. */
static int run_loadfix_inplace(const char *prog, const char *args) {
    return dos_exec_inplace(prog, args);
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

/* Fork-exec a child and wait for it. `poll_kbd` enables the Ctrl-Z =
 * background gesture used by the interactive launcher path; batch
 * lines pass 0. */
static int run_external_raw(const char *name, const char *args, int poll_kbd) {
    int pid;
    int rc;
    pid = synth_fork_exec(name, args);
    if (pid < 0) {
        printf("Bad command or file name: '%s'\r\n", name);
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
        vga_take(pid);
        return (int)exit_al;
    }
}

/* LOADFIX trampoline: re-fork COMMAND.COM with cmdline "/L prog [args]".
 * The trampoline child handles /L by running run_loadfix_inplace, which
 * dummy-allocs low memory and EXECs the program in its own address
 * space. Going through fork+exec (rather than EXEC-ing in this process)
 * keeps the interactive shell free to multitask. */
static int run_loadfix_via_trampoline(const char *prog, const char *args, int poll_kbd) {
    static char tail[128];
    if (args && *args) sprintf(tail, "/L %s %s", prog, args);
    else               sprintf(tail, "/L %s", prog);
    return run_external_raw("C:\\COMMAND.COM", tail, poll_kbd);
}

/* DOS/32A wrapper: launch C:\DOS32A.EXE with the original program and
 * args appended as command tail. DOS/32A loads the target itself and
 * supplies a stricter DPMI 0.9 environment than DOS/4GW's embedded one. */
static int run_via_dos32a(const char *prog, const char *args, int poll_kbd) {
    static char tail[200];
    if (args && *args) sprintf(tail, "%s %s", prog, args);
    else               strcpy(tail, prog);
    return run_external_raw("C:\\DOS32A.EXE", tail, poll_kbd);
}

static int run_external(const char *name, const char *args, int poll_kbd) {
    char resolved[80];
    unsigned char flags;
    if (!resolve_program(name, resolved)) {
        printf("Bad command or file name: '%s'\r\n", name);
        return 255;
    }
    if (has_ext(resolved, ".BAT")) return run_bat_file(resolved);
    flags = lookup_flags(resolved);
    if (flags & LF_F_DOS32A)  return run_via_dos32a(resolved, args, poll_kbd);
    if (flags & LF_F_LOADFIX) return run_loadfix_via_trampoline(resolved, args, poll_kbd);
    return run_external_raw(resolved, args, poll_kbd);
}

/* ----- built-ins ----- */

/* Does `p` start with `word` followed by end-of-string or whitespace? */
static int word_eq(const char *p, const char *word) {
    int i = 0;
    while (word[i]) {
        if (toupper((unsigned char)p[i]) != toupper((unsigned char)word[i])) return 0;
        i++;
    }
    return p[i] == 0 || p[i] == ' ' || p[i] == '\t';
}

static int builtin_echo(char *args) {
    char *p = skipws(args);
    if (*p == 0) {
        puts(echo_on ? "ECHO is on" : "ECHO is off");
        return 0;
    }
    if (word_eq(p, "ON"))  { echo_on = 1; return 0; }
    if (word_eq(p, "OFF")) { echo_on = 0; return 0; }
    puts(p);
    return 0;
}

static int builtin_cd(char *args) {
    char path[MAXPATH];
    char *p = skipws(args);
    int n;
    if (*p == 0) {
        if (getcwd(path, sizeof(path)) == 0) { puts("getcwd failed"); return 1; }
        puts(path);
        return 0;
    }
    n = 0;
    while (*p && *p != ' ' && *p != '\t' && n < (int)sizeof(path) - 1) path[n++] = *p++;
    path[n] = 0;
    if (chdir(path) != 0) { puts("Invalid directory"); return 1; }
    return 0;
}

static int builtin_cls(void) {
    clrscr();
    return 0;
}

static int builtin_type(char *args) {
    char path[128];
    char buf[256];
    char *p = skipws(args);
    FILE *f;
    int n, k = 0;
    if (*p == 0) { puts("Required parameter missing"); return 1; }
    while (*p && *p != ' ' && *p != '\t' && k < 127) path[k++] = *p++;
    path[k] = 0;
    f = fopen(path, "rb");
    if (f == 0) { puts("File not found"); return 1; }
    while ((n = (int)fread(buf, 1, sizeof(buf), f)) > 0) {
        fwrite(buf, 1, (size_t)n, stdout);
    }
    fclose(f);
    return 0;
}

static int builtin_pause(void) {
    printf("Press any key to continue . . .\n");
    getch();
    return 0;
}

static int try_builtin(const char *name, char *args, int *exit_code);

/* `trace <prog> [args]` -- enable the kernel DOS trace, run the given
 * command in the current process (no extra COMMAND.COM trampoline), then
 * disable trace before returning. The DN.EXT Ctrl+Enter binding uses this. */
static int builtin_trace(char *args) {
    char *p = skipws(args);
    char *prog, *prog_args;
    int exit_code = 0;
    if (*p == 0) {
        printf("Usage: trace <program> [args]\r\n");
        return 1;
    }
    prog = split_first(p, &prog_args);
    trace(1);
    if (!try_builtin(prog, prog_args, &exit_code)) {
        exit_code = run_external(prog, prog_args, 1);
    }
    trace(0);
    return exit_code;
}

/* If `name` is a built-in, run it and store its exit code in *exit_code,
 * then return 1. Otherwise return 0. EXIT terminates the process directly. */
static int try_builtin(const char *name, char *args, int *exit_code) {
    if (stricmp(name, "REM") == 0)   { *exit_code = 0; return 1; }
    if (stricmp(name, "ECHO") == 0)  { *exit_code = builtin_echo(args);  return 1; }
    if (stricmp(name, "CD") == 0 ||
        stricmp(name, "CHDIR") == 0) { *exit_code = builtin_cd(args);    return 1; }
    if (stricmp(name, "CLS") == 0)   { *exit_code = builtin_cls();       return 1; }
    if (stricmp(name, "TYPE") == 0)  { *exit_code = builtin_type(args);  return 1; }
    if (stricmp(name, "PAUSE") == 0) { *exit_code = builtin_pause();     return 1; }
    if (stricmp(name, "TRACE") == 0) { *exit_code = builtin_trace(args); return 1; }
    if (stricmp(name, "EXIT") == 0) {
        *exit_code = atoi(skipws(args));
        should_exit = 1;
        return 1;
    }
    return 0;
}

/* ----- batch interpreter ----- */

/* Execute one line of a .BAT file (no trailing CR/LF, NUL-terminated). */
static int run_bat_line(char *line) {
    char *p = skipws(line);
    char *prog, *args;
    int suppress_echo = 0;
    int exit_code = 0;

    if (*p == 0)   return 0;   /* blank */
    if (*p == ':') return 0;   /* label */
    if (*p == '@') { suppress_echo = 1; p++; p = skipws(p); }

    if (echo_on && !suppress_echo) puts(p);

    prog = split_first(p, &args);
    if (*prog == 0) return 0;

    if (try_builtin(prog, args, &exit_code)) return exit_code;
    return run_external(prog, args, 0);
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
    char args_buf[128];
    int exit_code = 0;
    int i = 1;
    int j;

    load_loadfix_cfg();

    printf("CMD argc=%d", argc);
    for (j = 1; j < argc; j++) printf(" [%s]", argv[j]);
    printf("\r\n");

    /* /L progname [args] -- LOADFIX trampoline entry. The interactive
     * COMMAND.COM forks us with this when it sees a name in loadfix.cfg;
     * we EXEC the program in-process so its PSP lands above segment
     * 0x1000 (dodging EXEPACK's load-low bug). */
    if (i < argc && is_flag(argv[i], 'L')) {
        i++;
        if (i >= argc) {
            printf("/L requires program name\r\n");
            return 1;
        }
        join_args(args_buf, sizeof(args_buf), argv, i + 1, argc);
        return run_loadfix_inplace(argv[i], args_buf);
    }

    /* Optional /C -- accept and skip (case-insensitive). */
    if (i < argc && is_flag(argv[i], 'C')) i++;

    if (i < argc) {
        join_args(args_buf, sizeof(args_buf), argv, i + 1, argc);
        if (!try_builtin(argv[i], args_buf, &exit_code)) {
            /* External -- interactive launcher mode (Ctrl-Z backgrounds). */
            exit_code = run_external(argv[i], args_buf, 1);
        }
    }

    return exit_code;
}
