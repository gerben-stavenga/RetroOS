/* COMMAND.COM -- minimal DOS shell launcher for RetroOS.
 *
 * Invoked one-shot as `COMMAND.COM /C cmdline` (or `COMMAND.COM cmdline`).
 * Parses its own PSP cmdline at DS:80h, then either:
 *   - runs a built-in (REM/ECHO/CD/CLS/TYPE/PAUSE/EXIT),
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
static int trace_active = 0;    /* /T flag: kernel DOS trace is on for this run */
static const char empty_str[] = "";

/* ----- thin INT wrappers ----- */

static void trace(int on) {
    r.h.ah = (unsigned char)(on ? 0x02 : 0x03);
    int86(0x31, &r, &r);
}

/* ----- LOADFIX list -----
 *
 * EXEPACK-compressed binaries (Borland CHESS, plenty of early-90s tools)
 * have a relocator bug that crashes when loaded below segment 0x1000.
 * Real DOS shipped LOADFIX.COM which allocated ~64 KB low, pushing the
 * program above 0x1000. RetroOS has no DOS resident eating low memory,
 * so every program loads below 0x1000 by default and EXEPACK trips on
 * "Packed file is corrupt".
 *
 * loadfix.cfg lists basenames (e.g. "CHESS.EXE") that need the
 * push-up. The kernel knows nothing about LOADFIX. We implement it
 * entirely here:
 *   1) interactive COMMAND.COM sees is_loadfix(name) and fork-execs
 *      itself with cmdline "/L <name> [args]" (multitasking preserved);
 *   2) the trampoline child takes the /L branch in main() and EXECs
 *      the target in-process via INT 21h AH=4B AL=00.
 *
 * The trampoline alone is the push-up: our COMMAND.COM is a tiny-model
 * .COM and so claims a full 64 KB block, exactly the shift real LOADFIX
 * provided. The EXEC'd child loads at PSP > 0x1000 and EXEPACK is happy.
 * No extra dummy alloc -- adding one would steal headroom from programs
 * with large minalloc (CHESS.EXE asks for ~440 KB) and break the load. */

#define LF_MAX_NAMES 32
#define LF_NAME_LEN  16
static char loadfix_names[LF_MAX_NAMES][LF_NAME_LEN];
static int  loadfix_count = 0;

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

static void load_loadfix_cfg(void) {
    FILE *f;
    char line[64];
    f = fopen("C:\\LOADFIX.CFG", "r");
    if (!f) return;
    while (loadfix_count < LF_MAX_NAMES && fgets(line, sizeof(line), f) != 0) {
        char *p = line + strspn(line, " \t");
        if (*p == 0 || *p == ';' || *p == '#' || *p == '\r' || *p == '\n') continue;
        p[strcspn(p, " \t\r\n")] = 0;
        if (strlen(p) == 0 || strlen(p) >= LF_NAME_LEN) continue;
        strcpy(loadfix_names[loadfix_count++], p);
    }
    fclose(f);
}

static int is_loadfix(const char *name) {
    const char *base = basename_of(name);
    int i;
    for (i = 0; i < loadfix_count; i++) {
        if (stricmp(base, loadfix_names[i]) == 0) return 1;
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

/* Copy our own PSP cmdline tail (DS:80h) into dst, NUL-terminated.
 * We work from PSP directly (not argc/argv) because DOS itself is flat:
 * INT 21h AH=4Bh wants a single command-tail string for the child's
 * PSP[0x80], not tokens, so we just slice this buffer in place. */
static void read_cmdline(char *dst, int max) {
    unsigned char far *psp = MK_FP(_psp, 0x80);
    int len = psp[0];
    int i;
    if (len > max - 1) len = max - 1;
    for (i = 0; i < len; i++) {
        unsigned char c = psp[1 + i];
        if (c == '\r') break;
        dst[i] = (char)c;
    }
    dst[i] = 0;
}

/* ----- kernel synth syscalls ----- */

static unsigned char get_child_exit_code(void);

static int synth_fork_exec(const char *name, const char *args) {
    segread(&s);
    r.h.ah = 0x01;
    r.x.dx = (unsigned)name;
    r.x.bx = (unsigned)args;
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
    return (int)get_child_exit_code();
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

static unsigned char get_child_exit_code(void) {
    r.h.ah = 0x4D;
    int86(0x21, &r, &r);
    return r.h.al;
}

/* Fork-exec a child and wait for it. `poll_kbd` enables the Ctrl-Z =
 * background gesture used by the interactive launcher path; batch
 * lines pass 0. */
static int run_external_raw(const char *name, const char *args, int poll_kbd) {
    int pid = synth_fork_exec(name, args ? args : empty_str);
    int rc;
    if (pid < 0) {
        puts("Bad command or file name");
        return 255;
    }
    for (;;) {
        rc = synth_waitpid(pid);
        if (rc < 0) return 255;
        if (rc == 0) break;
        if (poll_kbd) {
            while (kbhit()) {
                if (getch() == 0x1A) {
                    puts("[Backgrounded]");
                    return 0;
                }
            }
        }
    }
    vga_take(pid);
    return (int)get_child_exit_code();
}

/* LOADFIX trampoline: re-fork COMMAND.COM with cmdline "/L prog [args]".
 * The trampoline child handles /L by running run_loadfix_inplace, which
 * dummy-allocs low memory and EXECs the program in its own address
 * space. Going through fork+exec (rather than EXEC-ing in this process)
 * keeps the interactive shell free to multitask. */
static int run_loadfix_via_trampoline(const char *prog, const char *args, int poll_kbd) {
    static char tail[128];
    const char *tpfx = trace_active ? "/T " : "";
    if (args && *args) sprintf(tail, "%s/L %s %s", tpfx, prog, args);
    else               sprintf(tail, "%s/L %s", tpfx, prog);
    return run_external_raw("C:\\COMMAND.COM", tail, poll_kbd);
}

static int run_external(const char *name, const char *args, int poll_kbd) {
    char resolved[80];
    if (!resolve_program(name, resolved)) {
        puts("Bad command or file name");
        return 255;
    }
    if (has_ext(resolved, ".BAT")) return run_bat_file(resolved);
    if (is_loadfix(resolved)) return run_loadfix_via_trampoline(resolved, args, poll_kbd);
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

int main(void) {
    char cmdline[128];
    char *p, *prog, *args;
    int exit_code = 0;

    load_loadfix_cfg();

    read_cmdline(cmdline, sizeof(cmdline));
    p = skipws(cmdline);

    /* /T -- enable kernel DOS trace for this command. Off by default;
     * DN's "Ctrl+Enter" path turns it on via DN.EXT overrides. */
    if (p[0] == '/' && (p[1] == 'T' || p[1] == 't') &&
        (p[2] == 0 || p[2] == ' ' || p[2] == '\t')) {
        trace_active = 1;
        trace(1);
        p = skipws(p + 2);
    }

    /* /L progname [args] -- LOADFIX trampoline entry. The interactive
     * COMMAND.COM forks us with this when it sees a name in loadfix.cfg;
     * we EXEC the program in-process so its PSP lands above segment
     * 0x1000 (dodging EXEPACK's load-low bug). */
    if (p[0] == '/' && (p[1] == 'L' || p[1] == 'l') &&
        (p[2] == ' ' || p[2] == '\t')) {
        p = skipws(p + 2);
        prog = split_first(p, &args);
        exit_code = run_loadfix_inplace(prog, args);
        if (trace_active) trace(0);
        return exit_code;
    }

    /* Optional /C -- accept and skip (case-insensitive). */
    if (p[0] == '/' && (p[1] == 'C' || p[1] == 'c') &&
        (p[2] == 0 || p[2] == ' ' || p[2] == '\t')) {
        p = skipws(p + 2);
    }

    if (*p != 0) {
        /* Split program name from args in place -- no copy, no join.
         * `args` ends up pointing at the verbatim tail of our own cmdline,
         * which we hand straight to the kernel for the child's PSP[0x80]. */
        prog = split_first(p, &args);

        if (!try_builtin(prog, args, &exit_code)) {
            /* External -- interactive launcher mode (Ctrl-Z backgrounds). */
            exit_code = run_external(prog, args, 1);
        }
    }

    if (trace_active) trace(0);
    return exit_code;
}
