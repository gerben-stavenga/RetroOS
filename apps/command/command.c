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
static const char empty_str[] = "";

/* ----- thin INT wrappers ----- */

static void trace(int on) {
    r.h.ah = (unsigned char)(on ? 0x02 : 0x03);
    int86(0x31, &r, &r);
}

/* ----- string helpers ----- */

static int istreq(const char *a, const char *b) {
    while (*a && *b) {
        char ca = (char)toupper((unsigned char)*a);
        char cb = (char)toupper((unsigned char)*b);
        if (ca != cb) return 1;
        a++; b++;
    }
    return *a != *b;
}

static int ends_with_bat(const char *name) {
    int n = (int)strlen(name);
    if (n < 4) return 0;
    return (name[n-4] == '.' &&
            (name[n-3] & 0xDF) == 'B' &&
            (name[n-2] & 0xDF) == 'A' &&
            (name[n-1] & 0xDF) == 'T');
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

static int synth_fork_exec(const char *name, const char *args) {
    segread(&s);
    r.h.ah = 0x01;
    r.x.dx = (unsigned)name;
    r.x.bx = (unsigned)args;
    int86x(0x31, &r, &r, &s);
    if (r.x.cflag) return -1;
    return (int)r.x.bx;
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

/* Run a single external program. `poll_kbd` enables the Ctrl-Z = background
 * gesture used by the interactive launcher path; batch lines pass 0. */
static int run_external(const char *name, const char *args, int poll_kbd) {
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
    if (istreq(name, "REM") == 0)   { *exit_code = 0; return 1; }
    if (istreq(name, "ECHO") == 0)  { *exit_code = builtin_echo(args);  return 1; }
    if (istreq(name, "CD") == 0 ||
        istreq(name, "CHDIR") == 0) { *exit_code = builtin_cd(args);    return 1; }
    if (istreq(name, "CLS") == 0)   { *exit_code = builtin_cls();       return 1; }
    if (istreq(name, "TYPE") == 0)  { *exit_code = builtin_type(args);  return 1; }
    if (istreq(name, "PAUSE") == 0) { *exit_code = builtin_pause();     return 1; }
    if (istreq(name, "EXIT") == 0) {
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

    trace(1);

    read_cmdline(cmdline, sizeof(cmdline));
    p = skipws(cmdline);

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

        if (try_builtin(prog, args, &exit_code)) {
            /* handled */
        } else if (ends_with_bat(prog)) {
            exit_code = run_bat_file(prog);
        } else {
            /* External -- interactive launcher mode (Ctrl-Z backgrounds). */
            exit_code = run_external(prog, args, 1);
        }
    }

    trace(0);
    return exit_code;
}
