/* Enumerate /proc with GNU ps, then ask for a newly created child's identity. */
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    int pipefd[2], status;
    pid_t children[3];
    if (pipe(pipefd)) return 10;
    for (int i = 0; i < 3; i++) {
        children[i] = fork();
        if (children[i] < 0) return 11;
        if (!children[i]) {
            char byte;
            close(pipefd[1]);
            _exit(read(pipefd[0], &byte, 1) == 0 ? 0 : 17);
        }
    }
    char pid[24];
    snprintf(pid, sizeof(pid), "%d", children[2]);
    pid_t ps = fork();
    if (ps < 0) return 12;
    if (!ps) {
        execl("/bin/ps", "ps", "-p", pid, "-o", "stat=", "-o", "lstart=", (char *)0);
        _exit(13);
    }
    if (waitpid(ps, &status, 0) != ps) return 14;
    close(pipefd[1]);
    for (int i = 0; i < 3; i++) if (waitpid(children[i], NULL, 0) != children[i]) return 15;
    return WIFEXITED(status) ? WEXITSTATUS(status) : 16;
}
