/* COMMAND.COM -- minimal DOS shell launcher for RetroOS.
 *
 * Invoked one-shot as `COMMAND.COM /C cmdline` (or `COMMAND.COM cmdline`).
 * Reads its arguments through ANSI `int main(int argc, char *argv[])` (the
 * Borland C startup parses the PSP tail into argv); then either:
 *   - runs a built-in (REM/ECHO/CD/CLS/TYPE/COPY/PAUSE/TRACE/EXIT),
 *   - interprets a .BAT file line by line,
 *   - or fork+execs an external program and waits for it.
 *
 * The kernel-side INT 31h API is now layer-clean:
 *   AH=01h SYNTH_FORK_EXEC   DS:DX -> ASCIIZ program name
 *                            ES:BX -> ASCIIZ args (use "" for none)
 *                            -> CF=0 AX=0 BX=child_pid; CF=1 AX=errno
 *   AH=04h SYNTH_WAITPID     BX=pid -> CF=0 AX=0 exited / AX=1 alive
 *                            (peek only; slot stays Zombie until AH=05).
 *   AH=05h SYNTH_REAP        BX=pid -> recycle an exited child.
 *   AH=06h VGA_NEEDS_MODE3   -> AL=0 standard text / AL=1 normalize.
 *   AH=02/03h TRACE_ON/OFF
 *   AH=0Ah LOG_BYTE          AL=byte (kernel log only, never VGA)
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
#include <fcntl.h>
#include <io.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <alloc.h>

/* Keep this shell small. A .COM is handed a whole 64 KB segment, and the
 * tiny-model startup honours these to SETBLOCK it back down (measured: the
 * block goes from 0x1000 to ~0x6DC paragraphs, 64 KB -> 27 KB).
 *
 * It matters because a .BAT line is EXEC'd in THIS address space, so whatever
 * the shell holds is memory the game does not get: Hocus Pocus wants 567 KB
 * and refused to start with 11 KB missing. The LOADFIX path wants the 64 KB
 * back and asks for it explicitly (see set_block_size). */
unsigned _stklen  = 0x1000;
unsigned _heaplen = 0x1000;

static union REGS r;
static struct SREGS s;
static int echo_on = 1;
static int should_exit = 0;     /* set by EXIT builtin to break out of BAT */
/* Nonzero while a .BAT is being interpreted. Batch lines run in THIS address
 * space (in-process EXEC) rather than forking, so a TSR loaded by one line is
 * still resident for the next — see dispatch_external. */
static int in_batch = 0;
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
 *     INT 21h AH=4B AL=00. The trampoline itself is the push-up: the /L
 *     child grows its own block back to a full 64 KB first (see
 *     set_block_size), exactly the shift real LOADFIX provided.
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
#define LF_F_IOPL3   0x04
#define LF_F_REPAIR  0x08

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
    if (stricmp(tok, "iopl3")   == 0) return LF_F_IOPL3;
    if (stricmp(tok, "repair")  == 0) return LF_F_REPAIR;
    return 0;
}

static void load_loadfix_cfg(void) {
    FILE *f;
    char line[80];
    /* Embedded bootfs (always present, always mounted at C:\BOOT) -- robust
     * vs the ext4 root mounting at C:\DISK1 instead of C:\ on real installs. */
    f = fopen("C:\\BOOT\\LOADFIX.CFG", "r");
    if (!f) return;
    while (loadfix_count < LF_MAX_NAMES && fgets(line, sizeof(line), f) != 0) {
        char *p = line + strspn(line, " \t");
        char *name, *tok;
        unsigned char flags = 0;
        int overlong = strchr(line, '\n') == 0 && !feof(f);
        /* A line longer than the buffer arrives in pieces, and the TAIL does not
         * start with '#' -- so it would be parsed as a program entry, quietly
         * filling the table with junk and shifting the real entries out. A long
         * COMMENT then silently disables the policy for a game: DOOM lost its
         * `repair` flag that way, fell back to the legacy loadfix default at
         * vIOPL=1, and hung at DMX_Init with virtual IF stuck off. Never let a
         * line's overflow become a record: drop the whole line. */
        if (overlong) {
            int c;
            while ((c = fgetc(f)) != EOF && c != '\n') { }
            continue;
        }
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
 * and we do the same -- the kernel sees the resolved path we selected,
 * not the user's bare command token. */

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

/* Path to this command interpreter for recursive COMMAND.COM launches
 * (LOADFIX trampoline). Prefer COMSPEC, but cache an absolute-ish copy at
 * startup so changing directories does not break a later /L re-fork. */
static char command_com_path[MAXPATH] = "COMMAND.COM";

static void copy_path(char *dst, const char *src) {
    strncpy(dst, src, MAXPATH - 1);
    dst[MAXPATH - 1] = 0;
}

static int is_abs_dos_path(const char *p) {
    return p && p[0] && p[1] == ':' && (p[2] == '\\' || p[2] == '/');
}

static int make_abs_path(const char *path, char *out) {
    char cwd[MAXPATH];
    size_t clen, plen;
    if (!path || !*path) return 0;
    if (is_abs_dos_path(path)) {
        copy_path(out, path);
        return 1;
    }
    if (getcwd(cwd, sizeof(cwd)) == 0) {
        copy_path(out, path);
        return 1;
    }
    if (path[0] == '\\' || path[0] == '/') {
        if (!(cwd[0] && cwd[1] == ':')) {
            copy_path(out, path);
            return 1;
        }
        plen = strlen(path);
        if (2 + plen >= MAXPATH) return 0;
        out[0] = cwd[0];
        out[1] = ':';
        strcpy(out + 2, path);
        return 1;
    }
    clen = strlen(cwd);
    plen = strlen(path);
    if (clen + (clen > 0 && cwd[clen - 1] != '\\' ? 1 : 0) + plen >= MAXPATH) return 0;
    strcpy(out, cwd);
    if (clen > 0 && out[clen - 1] != '\\') strcat(out, "\\");
    strcat(out, path);
    return 1;
}

static int set_command_path_if_exists(const char *path) {
    char abs[MAXPATH];
    if (!path || !*path || !file_exists(path)) return 0;
    if (!make_abs_path(path, abs)) return 0;
    copy_path(command_com_path, abs);
    return 1;
}

static void init_command_path(const char *argv0) {
    char resolved[MAXPATH];
    char *comspec = getenv("COMSPEC");
    if (set_command_path_if_exists(comspec)) return;
    if (set_command_path_if_exists(argv0)) return;
    if (argv0 && *argv0 && resolve_program(argv0, resolved) &&
        set_command_path_if_exists(resolved)) return;
    if (resolve_program("COMMAND.COM", resolved) &&
        set_command_path_if_exists(resolved)) return;
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

static int synth_fork_exec(const char *name, const char *args, unsigned char viopl) {
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
    /* CL = child's virtual IOPL: 3 = `iopl3` (DOOM/DOOM2/Hexen), else the
     * spec-conforming default of 1. Set explicitly -- the global `r` union
     * is reused, so a stale CL could otherwise leak IOPL=3 into a plain
     * launch. The kernel reads CL in INT 31h AH=01 (dos.rs SYNTH_FORK_EXEC). */
    r.x.cx = viopl;
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

/* Resize our own memory block to `paras` paragraphs (INT 21h AH=4Ah).
 *
 * The startup shrinks us to roughly _heaplen+_stklen so a batch line EXEC'd
 * in-process gets nearly all of conventional memory — Hocus Pocus wants 567 KB
 * and a 64 KB shell left it 11 KB short. But the LOADFIX trampoline needs the
 * opposite: it exists to push the program's PSP above segment 0x1000, and the
 * shell's own block IS that push. So /L grows back to 0x1000 paragraphs first.
 * Failure is not fatal — the EXEC just loads lower, exactly as before. */
static void set_block_size(unsigned paras) {
    r.h.ah = 0x4A;
    r.x.bx = paras;
    s.es   = _psp;
    s.ds   = _psp;
    int86x(0x21, &r, &r, &s);
}

/* Set THIS thread's virtual IOPL (the kernel's IfMode) via INT 31h AH=09h.
 * Fork-exec passes the child's mode in CL because the child is a new thread;
 * an in-process EXEC runs on ours, so batch lines set it here instead. */
static void synth_set_viopl(unsigned char viopl) {
    r.h.ah = 0x09;
    r.x.cx = viopl;
    int86(0x31, &r, &r);
}

static int synth_waitpid(int pid) {
    r.h.ah = 0x04;
    r.x.bx = (unsigned)pid;
    int86(0x31, &r, &r);
    if (r.x.cflag) return -1;
    return (int)r.x.ax;   /* 0 = exited, 1 = still alive */
}

/* INT 31h AH=06h: inspect our current live VGA without changing it. A normal
 * child return handed us the adapter itself, so its text screen is already
 * the implicit return value; no zombie snapshot needs adopting. */
static int synth_vga_needs_mode3(void) {
    r.h.ah = 0x06;
    int86(0x31, &r, &r);
    if (r.x.cflag) return -1;
    return (int)r.h.al;
}

/* COMMAND.COM is a function inside its DOS caller, not another RetroOS
 * address space. Preserve a proper child exit-text screen verbatim; only ask
 * the BIOS for mode 3 when the live adapter is not a conventional 80x25
 * colour-text environment the caller can paint into. */
static void ensure_standard_text_mode(void) {
    if (synth_vga_needs_mode3() != 0) {
        r.x.ax = 0x0003;
        int86(0x10, &r, &r);
    }
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

/* Re-seed the BIOS tick-of-day counter (40:6C) from the RTC. A fork-exec'd
 * child runs in its own address space with its own BDA; while we sit in the
 * waitpid loop our timer IRQs coalesce, so our copy of the counter falls
 * behind by however long the child ran. INT 1A AH=02 reads the RTC (BCD),
 * AH=01 stores the recomputed count. */
static void refresh_bda_clock(void) {
    unsigned long secs, ticks;
    r.h.ah = 0x02;
    int86(0x1A, &r, &r);
    if (r.x.cflag) return;
    secs = 3600UL * (unsigned char)((r.h.ch >> 4) * 10 + (r.h.ch & 0x0F))
         +   60UL * (unsigned char)((r.h.cl >> 4) * 10 + (r.h.cl & 0x0F))
         +          (unsigned char)((r.h.dh >> 4) * 10 + (r.h.dh & 0x0F));
    /* ticks = secs * 1193182 / 65536 = secs * 18.20651 Hz, kept in 32 bits:
     * secs*2065 <= 86399*2065 < 2^32. */
    ticks = secs * 18UL + (secs * 2065UL) / 10000UL;
    r.h.ah = 0x01;
    r.x.cx = (unsigned)(ticks >> 16);
    r.x.dx = (unsigned)(ticks & 0xFFFF);
    int86(0x1A, &r, &r);
}

/* Fork-exec a child and wait for it. argv[0] = program path,
 * argv[1..argc-1] = args. The args are joined into the cmdline tail
 * right here at the synth call boundary so callers stay tokenised.
 * `interactive` means that being scheduled again while the child is still
 * alive is an OSD task switch back to our caller, so release it immediately.
 * Batch lines pass 0 and continue waiting for their child. */
static int run_external_raw(char **argv, int argc, int interactive, unsigned char viopl) {
    char tail[128];
    int pid, rc;
    join_args(tail, sizeof(tail), argv, 1, argc);
    pid = synth_fork_exec(argv[0], tail, viopl);
    if (pid < 0) {
        printf("Bad command or file name: '%s'\r\n", argv[0]);
        return 255;
    }
    for (;;) {
        rc = synth_waitpid(pid);
        if (rc < 0) return 255;          /* no such child / EINVAL */
        if (rc == 0) break;              /* exited */
        if (interactive) {
            /* OSD already restored the caller's VGA snapshot when it moved
             * focus back here. This is a pure function return: touching the
             * mode or framebuffer would destroy screens (DN in particular)
             * whose contents are the caller's saved execution state. */
            return 0;
        }
    }
    refresh_bda_clock();
    {
        unsigned int status = get_child_exit_status();
        unsigned char term_type = (unsigned char)(status >> 8);
        unsigned char exit_al   = (unsigned char)(status & 0xFF);
        if (term_type == 0x02) {
            /* Critical error/fault restored our pre-child recovery screen. */
            synth_reap(pid);
            ensure_standard_text_mode();
            printf("Aborted (critical error)\r\n");
            printf("Reaped child %d with exit status %02Xh\r\n", pid, exit_al);
            return 1;
        }
        /* Normal/TSR exit transferred the live VGA to us; Ctrl-Break already
         * restored our recovery image. Reaping only frees bookkeeping; then
         * preserve valid text output or normalize graphics once, immediately
         * before returning to our in-process caller. */
        synth_reap(pid);
        ensure_standard_text_mode();
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
static int dispatch_external(char **argv, int prog_idx, int argc, int interactive) {
    char resolved[80];
    unsigned char flags;
    unsigned char viopl;
    if (prog_idx >= argc) return 0;
    assert(prog_idx >= 2);
    if (!resolve_program(argv[prog_idx], resolved)) {
        printf("Bad command or file name: '%s'\r\n", argv[prog_idx]);
        return 255;
    }
    if (has_ext(resolved, ".BAT")) {
        /* A .BAT gets its OWN address space.
         *
         * Batch lines are EXEC'd in-process so a TSR loaded by one line is
         * still resident for the next. That only stays safe if the batch is
         * isolated first: interpreting it inline runs every line — the TSR
         * and the game it loads — in the CALLER's address space, which is
         * DN's. Hocus Pocus then corrupted DN, which crashed on return.
         *
         * So fork a fresh COMMAND.COM in /B mode, exactly as the LOADFIX
         * trampoline re-forks for /L. The child owns a clean address space
         * with all of conventional memory, runs the lines in-process inside
         * it, and takes the TSR down with it when the batch ends. Already
         * inside a batch (nested .BAT) we are that child, so run it inline. */
        if (in_batch) return run_bat_file(resolved);
        prog_idx -= 2;   /* claim the two scratch slots for the trampoline */
        argv[prog_idx] = command_com_path;
        argv[prog_idx + 1] = "/B";
        argv[prog_idx + 2] = resolved;
        return run_external_raw(&argv[prog_idx], argc - prog_idx, interactive, 1);
    }
    argv[prog_idx] = resolved;
    flags = lookup_flags(resolved);
    /* Virtual-IF mode (the kernel's `IfMode`), passed as the child's vIOPL:
     *   1 = iopl1  spec-strict: POPF/IRET are ignored, per DPMI 0.9 2.13.
     *   2 = repair honor them, caught by a learned exit breakpoint. Cheap.
     *   3 = iopl3  honor them by single-stepping the window. The always-correct
     *              reference path, ~2500x slower — the escape hatch for a
     *              client `repair` mispredicts.
     * A client that re-enables IF the sloppy way HANGS at iopl1 (DOOM et al),
     * so `repair` is what games want; `iopl3` stays available to fall back to. */
    viopl = (flags & LF_F_IOPL3) ? 3 : (flags & LF_F_REPAIR) ? 2 : 1;
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
        argv[prog_idx] = command_com_path;
        argv[prog_idx + 1] = "/L";
    }
    /* Inside a .BAT, run the line in OUR address space instead of forking.
     *
     * A batch file is one shell session, and DOS ran each line as an
     * in-process EXEC into the single conventional-memory map. That is what
     * makes `TSR` on one line visible to the program on the next: the
     * resident block stays in the MCB chain and its interrupt hooks stay in
     * the shared IVT. Fork-exec gives every line a private address space with
     * a private page-0 IVT, so a TSR dies with the line that loaded it —
     * HOCUSG.BAT loads ULTRAMID, then the game reports "UltraMID not found".
     *
     * The LOADFIX trampoline is skipped here: it exists only to re-fork
     * COMMAND.COM so the program's PSP lands above segment 0x1000, and an
     * in-process EXEC already loads above this interpreter's own block.
     * DOS/32A prefixing above still applies — that is just a different
     * program to exec, and it works in-process unchanged.
     */
    if (in_batch) {
        char tail[128];
        int rc;
        int start = (flags & LF_F_LOADFIX) ? prog_idx + 2 : prog_idx;
        join_args(tail, sizeof(tail), argv, start + 1, argc);
        synth_set_viopl(viopl);
        rc = dos_exec_inplace(argv[start], tail);
        synth_set_viopl(1);      /* back to the shell's own spec-strict mode */
        refresh_bda_clock();
        return rc;
    }
    return run_external_raw(&argv[prog_idx], argc - prog_idx, interactive, viopl);
}

/* ----- built-ins -----
 *
 * All builtins take (argv, argc) where argv[0] is the command name (so
 * argv[1..argc-1] are the arguments). Mirrors the int main() convention,
 * keeps tokenisation in a single place (the BAT-line / cmdline parser). */

/* ----- COPY -----
 *
 * COPY is internal to COMMAND.COM on real DOS -- there is no COPY.EXE -- so a
 * missing built-in surfaces as "Bad command or file name", which is how an
 * installer shelling out to COPY fails. The forms installers actually emit:
 *
 *   COPY SRC DEST          file -> file
 *   COPY SRC DIR           file -> directory (keeps the name)
 *   COPY A:\*.* C:\GAME    wildcard fan-out into a directory
 *   COPY A:\*.* C:\GAME\*.*  same, with the redundant pattern spelled out
 *   COPY A:\SUBDIR C:\DST  a bare directory source means SUBDIR\*.*
 *   COPY A+B+C DEST        concatenation (also `COPY A + B DEST`)
 *   COPY SRC               into the current directory
 *
 * /A /B /V /Y /-Y are accepted and ignored: there is no ASCII/binary split
 * here (every copy is a byte-for-byte binary copy), no verify pass, and an
 * existing destination is always overwritten. */

/* Keep only a one-sector fallback resident: BSS in this shell is memory a
 * batch line's in-process EXEC cannot use (see _stklen above).  During COPY,
 * borrow a separate 16 KiB DOS block from the far heap.  Large installer
 * resources otherwise cross the INT 21h/emulator boundary twice per 512-byte
 * sector, turning a 20 MiB install into roughly 80,000 syscalls. */
#define COPY_BUF_SIZE 16384U
static char copy_fallback_buf[512];
static int copy_quiet = 0;       /* COPY ... >NUL: keep installer UIs intact */

/* Normal COPY output goes through DOS stdout, whose console path also mirrors
 * it into the kernel log.  For >NUL keep only that second half via the
 * LOG_BYTE synth call, so diagnostics remain in retroos.log without painting
 * over the caller's VGA text UI. */
static void copy_report(const char *fmt, ...) {
    char msg[128];
    char *p;
    va_list ap;
    va_start(ap, fmt);
    vsprintf(msg, fmt, ap);
    va_end(ap);
    if (!copy_quiet) {
        fputs(msg, stdout);
        return;
    }
    for (p = msg; *p; p++) {
        r.h.ah = 0x0A;
        r.h.al = (unsigned char)*p;
        int86(0x31, &r, &r);
    }
}

static int copy_read(int fd, void far *buf, unsigned count) {
    r.h.ah = 0x3F;
    r.x.bx = (unsigned)fd;
    r.x.cx = count;
    r.x.dx = FP_OFF(buf);
    s.ds = FP_SEG(buf);
    int86x(0x21, &r, &r, &s);
    return r.x.cflag ? -1 : (int)r.x.ax;
}

static int copy_write(int fd, const void far *buf, unsigned count) {
    r.h.ah = 0x40;
    r.x.bx = (unsigned)fd;
    r.x.cx = count;
    r.x.dx = FP_OFF(buf);
    s.ds = FP_SEG(buf);
    int86x(0x21, &r, &r, &s);
    return r.x.cflag ? -1 : (int)r.x.ax;
}

/* INT 21h AX=4300h -- attribute word, or 0 when the path does not exist. */
static int dos_file_attr(const char *path, unsigned *attr) {
    const char far *fpath = path;
    r.x.ax = 0x4300;
    r.x.dx = FP_OFF(fpath);
    s.ds   = FP_SEG(fpath);
    s.es   = FP_SEG(fpath);
    int86x(0x21, &r, &r, &s);
    if (r.x.cflag) return 0;
    *attr = r.x.cx;
    return 1;
}

/* Directory part of `path` including its trailing separator; "" if none. */
static void copy_dir_prefix(const char *path, char *out) {
    const char *base = basename_of(path);
    size_t n = (size_t)(base - path);
    if (n > MAXPATH - 1) n = MAXPATH - 1;
    memcpy(out, path, n);
    out[n] = 0;
}

static void copy_join(char *out, const char *dir, const char *name) {
    size_t dlen = strlen(dir);
    if (dlen > MAXPATH - 1) dlen = MAXPATH - 1;
    memcpy(out, dir, dlen);
    out[dlen] = 0;
    strncat(out, name, MAXPATH - 1 - dlen);
}

/* Is the destination a place to put files rather than a name to give them? */
static int copy_dest_is_dir(const char *dest) {
    unsigned attr;
    size_t n = strlen(dest);
    if (n == 0) return 1;
    if (strchr("\\/:", dest[n - 1])) return 1;      /* "C:\DIR\", "C:", "\" */
    if (strcmp(dest, ".") == 0 || strcmp(dest, "..") == 0) return 1;
    if (strpbrk(dest, "*?")) return 0;              /* a renaming pattern */
    return dos_file_attr(dest, &attr) && (attr & FA_DIREC);
}

/* Destination directory as a prefix, i.e. carrying its trailing separator.
 * "." collapses to an empty prefix so `COPY F .` builds the same path as F
 * itself and is caught as a copy-onto-itself instead of truncating it. */
static void copy_dest_dir(char *out, const char *dest) {
    size_t n = strlen(dest);
    if (n == 0 || strcmp(dest, ".") == 0) { out[0] = 0; return; }
    if (n > MAXPATH - 2) n = MAXPATH - 2;
    memcpy(out, dest, n);
    out[n] = 0;
    if (!strchr("\\/:", out[n - 1])) { out[n] = '\\'; out[n + 1] = 0; }
}

/* Split a DOS name into its 8-char stem and 3-char extension. */
static void copy_split_name(const char *s, char *base, char *ext) {
    const char *dot = strchr(s, '.');
    size_t n;
    if (dot) {
        n = (size_t)(dot - s);
        if (n > 8) n = 8;
        memcpy(base, s, n);
        base[n] = 0;
        strncpy(ext, dot + 1, 3);
        ext[3] = 0;
    } else {
        strncpy(base, s, 8);
        base[8] = 0;
        ext[0] = 0;
    }
}

/* Map one field (stem or extension) of `src` through wildcard `pat`: '*' takes
 * the rest of the source field, '?' takes one source character, anything else
 * is a literal that consumes a source character. */
static void copy_map_field(const char *pat, const char *src, char *out, int max) {
    int pi = 0, si = 0, oi = 0;
    while (pat[pi] && oi < max) {
        if (pat[pi] == '*') {
            while (src[si] && oi < max) out[oi++] = src[si++];
            break;
        }
        if (pat[pi] == '?') {
            if (src[si]) out[oi++] = src[si++];
        } else {
            out[oi++] = pat[pi];
            if (src[si]) si++;
        }
        pi++;
    }
    out[oi] = 0;
}

/* Destination name for source `name` under destination pattern `pattern`:
 * "*.*" leaves it alone, "*.BAK" keeps the stem, "NEW.*" keeps the extension. */
static void copy_map_name(const char *pattern, const char *name, char *out) {
    char pbase[13], pext[5], sbase[13], sext[5], obase[13], oext[5];
    copy_split_name(pattern, pbase, pext);
    copy_split_name(name, sbase, sext);
    /* A pattern with no dot ("DIR\*") means "any extension", as DOS reads it;
     * taking the empty field literally would silently drop extensions. */
    if (!strchr(pattern, '.')) strcpy(pext, "*");
    copy_map_field(pbase, sbase, obase, 8);
    copy_map_field(pext, sext, oext, 3);
    if (oext[0]) sprintf(out, "%s.%s", obase, oext);
    else strcpy(out, obase);
}

/* Textual same-file test. Both sides are made absolute first so `COPY F .`
 * and `COPY C:\DIR\F F` from C:\DIR are recognised before the destination is
 * created -- creating it truncates, so this check must precede it. */
static int copy_same_file(const char *a, const char *b) {
    char pa[MAXPATH], pb[MAXPATH];
    if (!make_abs_path(a, pa)) copy_path(pa, a);
    if (!make_abs_path(b, pb)) copy_path(pb, b);
    return stricmp(pa, pb) == 0;
}

/* Byte-for-byte copy of one file. `append` seeks an existing destination to
 * its end instead of truncating -- that is how several sources accumulate
 * into a single named destination. Returns 1 on success. */
static int copy_file(const char *src, const char *dst, int append) {
    int in, out, n;
    unsigned buflen = COPY_BUF_SIZE;
    void far *buf = farmalloc((unsigned long)COPY_BUF_SIZE);
    int far_buf = buf != 0;
    if (!buf) {
        buf = copy_fallback_buf;
        buflen = sizeof(copy_fallback_buf);
    }
    in = open(src, O_RDONLY | O_BINARY);
    if (in < 0) {
        if (far_buf) farfree(buf);
        copy_report("Cannot open %s\r\n", src);
        return 0;
    }
    out = -1;
    if (append) {
        out = open(dst, O_WRONLY | O_BINARY);
        if (out >= 0 && lseek(out, 0L, SEEK_END) < 0L) { close(out); out = -1; }
    }
    if (out < 0) out = _creat(dst, 0);
    if (out < 0) {
        close(in);
        if (far_buf) farfree(buf);
        copy_report("Cannot create %s\r\n", dst);
        return 0;
    }
    while ((n = copy_read(in, buf, buflen)) > 0) {
        if (copy_write(out, buf, (unsigned)n) != n) {
            close(in);
            close(out);
            if (far_buf) farfree(buf);
            copy_report("Insufficient disk space\r\n");
            return 0;
        }
    }
    close(in);
    close(out);
    if (far_buf) farfree(buf);
    if (n < 0) { copy_report("Read error - %s\r\n", src); return 0; }
    return 1;
}

/* Copy everything matching one source spec. `destpat` non-NULL means "into
 * destdir, naming files through this pattern"; NULL means "the single file
 * destfile", in which case sources after the first append to it. */
static int copy_source(const char *src, const char *destdir, const char *destpat,
                       const char *destfile, int *copied, int *opened) {
    struct ffblk ff;
    char spec[MAXPATH];
    char srcdir[MAXPATH];
    char from[MAXPATH];
    char to[MAXPATH];
    unsigned attr;
    int wild, done, rc = 0;

    copy_path(spec, src);
    /* A bare directory source means every file in it, as DOS expands it. */
    if (!strpbrk(spec, "*?") && dos_file_attr(spec, &attr) && (attr & FA_DIREC)) {
        size_t n = strlen(spec);
        if (n + 5 >= MAXPATH) {
            copy_report("Invalid path - %s\r\n", src);
            return 1;
        }
        if (n > 0 && !strchr("\\/:", spec[n - 1])) spec[n++] = '\\';
        strcpy(spec + n, "*.*");
    }
    wild = strpbrk(spec, "*?") != 0;
    copy_dir_prefix(spec, srcdir);

    done = findfirst(spec, &ff, 0);
    if (done != 0) {
        copy_report("File not found - %s\r\n", src);
        return 1;
    }
    for (; done == 0; done = findnext(&ff)) {
        if (ff.ff_attrib & FA_DIREC) continue;
        copy_join(from, srcdir, ff.ff_name);
        if (destpat) {
            char name[13];
            copy_map_name(destpat, ff.ff_name, name);
            copy_join(to, destdir, name);
        } else {
            copy_path(to, destfile);
        }
        if (copy_same_file(from, to)) {
            copy_report("File cannot be copied onto itself - %s\r\n", from);
            rc = 1;
            continue;
        }
        /* DOS lists the sources of a multi-file copy as it walks them. */
        if (wild) copy_report("%s\r\n", ff.ff_name);
        if (!copy_file(from, to, destpat == 0 && *opened)) { rc = 1; continue; }
        if (destpat == 0) *opened = 1;
        (*copied)++;
    }
    return rc;
}

static int copy_cmd(char **argv, int args, int argc) {
    char *toks[MAX_ARGV];
    char destdir[MAXPATH];
    const char *destpat;
    const char *destfile;
    int ntok = 0, i, copied = 0, opened = 0, rc = 0;

    /* Drop switches, then split any attached "A+B+C" chain into its members.
     * A standalone "+" (from `COPY A + B DEST`) falls out as an empty token. */
    for (i = args; i < argc; i++) {
        char *t = argv[i];
        if (t[0] == '/') continue;
        if (t[0] == '-' && (t[1] == 'Y' || t[1] == 'y') && t[2] == 0) continue;
        while (t != 0 && ntok < MAX_ARGV) {
            char *plus = strchr(t, '+');
            if (plus) *plus = 0;
            if (*t) toks[ntok++] = t;
            t = plus ? plus + 1 : 0;
        }
    }
    if (ntok == 0) {
        copy_report("Required parameter missing\r\n");
        return 1;
    }

    if (ntok == 1) {
        /* No destination: the current directory, same names. */
        destdir[0] = 0;
        destpat = "*.*";
        destfile = 0;
    } else {
        const char *dest = toks[--ntok];
        const char *base = basename_of(dest);
        if (copy_dest_is_dir(dest)) {
            copy_dest_dir(destdir, dest);
            destpat = "*.*";
            destfile = 0;
        } else if (strpbrk(base, "*?")) {
            copy_dir_prefix(dest, destdir);
            destpat = base;
            destfile = 0;
        } else {
            destdir[0] = 0;
            destpat = 0;
            destfile = dest;
        }
    }

    for (i = 0; i < ntok; i++) {
        rc |= copy_source(toks[i], destdir, destpat, destfile, &copied, &opened);
    }
    copy_report("%8d file(s) copied\r\n", copied);
    return (rc || copied == 0) ? 1 : 0;
}

/* The shell does not yet redirect handles, but redirection syntax must still
 * be consumed by the shell rather than handed to a builtin or child as an
 * ordinary filename.  In particular, Gremlin's installer appends ` >NUL` to
 * every COPY command.  Treating that token as COPY's destination copied the
 * source into a literal NUL~1 file, then treated the intended destination as
 * another source.  A bare operator consumes the following filename; an
 * attached operator such as >NUL or 2>LOG consumes only its own token. */
static int strip_redirections(char **argv, int prog_idx, int argc,
                              int *stdout_nul) {
    int i = prog_idx + 1;
    while (i < argc) {
        char *p = argv[i];
        int separate;
        int skip;
        if (isdigit((unsigned char)*p) && (p[1] == '>' || p[1] == '<')) p++;
        if (*p != '>' && *p != '<') { i++; continue; }
        separate = p[1] == 0 || (p[0] == '>' && p[1] == '>' && p[2] == 0);
        if (*p == '>') {
            char *target = p + 1;
            if (*target == '>') target++;
            if (*target == 0 && i + 1 < argc) target = argv[i + 1];
            if (stricmp(target, "NUL") == 0) *stdout_nul = 1;
        }
        skip = separate && i + 1 < argc ? 2 : 1;
        while (i + skip < argc) {
            argv[i] = argv[i + skip];
            i++;
        }
        argc -= skip;
        i = prog_idx + 1;
    }
    return argc;
}

/* Run the command at argv[prog_idx] with arguments at argv[prog_idx+1..argc-1].
 * Built-ins (drive switch "X:", REM/ECHO/CD/CLS/TYPE/COPY/LOG/PAUSE/TRACE/EXIT/
 * SHUTDOWN) are matched first and handled inline; if none match,
 * dispatch_external takes over at the tail.
 * argv[prog_idx-1] and argv[prog_idx-2] (when prog_idx >= 1 / >= 2) must be
 * caller-reserved scratch slots that dispatch_external may overwrite for
 * trampoline-prefix injection. Returns the command's exit code. */
static int run_command(char **argv, int prog_idx, int argc, int interactive) {
    const char *name;
    int args;
    int nargs;
    int stdout_nul = 0;

    if (prog_idx >= argc) return 0;
    argc = strip_redirections(argv, prog_idx, argc, &stdout_nul);
    args = prog_idx + 1;                /* index of first argument token */
    nargs = argc - args;                /* number of argument tokens */
    name = argv[prog_idx];

    /* Bare "X:" switches the current drive. AH=0Eh reports LASTDRIVE rather
     * than an error for a bad letter, so read the drive back (AH=19h) to
     * detect one. */
    if (isalpha((unsigned char)name[0]) && name[1] == ':' && name[2] == 0) {
        unsigned char want = (unsigned char)(toupper((unsigned char)name[0]) - 'A');
        r.h.ah = 0x0E;
        r.h.dl = want;
        int86(0x21, &r, &r);
        r.h.ah = 0x19;
        int86(0x21, &r, &r);
        if (r.h.al != want) { puts("Invalid drive specification"); return 1; }
        return 0;
    }

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
    if (stricmp(name, "COPY") == 0) {
        int rc;
        copy_quiet = stdout_nul;
        rc = copy_cmd(argv, args, argc);
        copy_quiet = 0;
        return rc;
    }
    if (stricmp(name, "LOG") == 0) {
        /* Dump the in-memory kernel log (INT 31h AH=07h, line by line). On real
         * metal this is the only way to read kernel/dbg_println output back --
         * the 0xE9 debug port is unconnected on actual hardware. BX = line
         * index; CF=1 ends the loop. */
        static char buf[520];
        unsigned i;
        for (i = 0; ; i++) {
            const char far *fbuf = buf;
            r.h.ah = 0x07;
            r.x.bx = i;
            r.x.di = FP_OFF(fbuf);
            s.es   = FP_SEG(fbuf);
            int86x(0x31, &r, &r, &s);
            if (r.x.cflag) break;
            buf[r.x.cx] = 0;
            puts(buf);
        }
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
        rc = run_command(argv, args, argc, interactive);
        trace(0);
        return rc;
    }
    if (stricmp(name, "EXIT") == 0) {
        should_exit = 1;
        return (nargs > 0) ? atoi(argv[args]) : 0;
    }
    if (stricmp(name, "SHUTDOWN") == 0) {
        /* Park the audio hardware and halt via the kernel (INT 31h AH=08h).
         * Always leave real hardware this way instead of the power button: a
         * hard power-off while the HDA codec is streaming wedges it (deaf to
         * every OS) until a cold power cycle. The kernel prints its own
         * "safe to turn off" line and never returns; after it, holding the
         * power button is harmless. */
        r.h.ah = 0x08;
        int86(0x31, &r, &r);
        puts("Shutdown failed");   /* not reached on any working kernel */
        return 1;
    }

    /* Tail: not a built-in -- spawn as external program. */
    return dispatch_external(argv, prog_idx, argc, interactive);
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
    in_batch++;
    while (fgets(line, sizeof(line), f) != 0) {
        int n = (int)strlen(line);
        while (n > 0 && (line[n-1] == '\r' || line[n-1] == '\n')) line[--n] = 0;
        last = run_bat_line(line);
        if (should_exit) break;
    }
    in_batch--;
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
    init_command_path(argc > 0 ? argv[0] : 0);
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
    if (argc < 2 || (!is_flag(argv[1], 'L') && !is_flag(argv[1], 'C')
                     && !is_flag(argv[1], 'B'))) {
        printf("Usage: COMMAND.COM /C cmdline   (/L LOADFIX, /B batch)\r\n");
        return 1;
    }

    /* /B batfile -- batch trampoline entry. We are a fresh fork with our own
     * address space; interpret the file here so its lines (and any TSR they
     * leave resident) are confined to it. */
    if (is_flag(argv[1], 'B')) {
        if (argc < 3) {
            printf("/B requires a batch file\r\n");
            return 1;
        }
        return run_bat_file(argv[2]);
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
        /* Restore the 64 KB claim: this block is the LOADFIX push-up. */
        set_block_size(0x1000);
        return dos_exec_inplace(argv[2], tail);
    }

    /* /C path: argv[2] is the program/builtin, argv[3..] are its args.
     * argv[0] and argv[1] are guaranteed scratch for trampoline prefixes.
     * Interactive launcher mode -- an OSD switch back to this task releases
     * the still-running child and returns directly to the caller. */
    return run_command(argv, 2, argc, 1);
}
