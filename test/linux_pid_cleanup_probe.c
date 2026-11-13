#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

/* A process wrapper may reap its child before cleaning up that child's
 * process group. Match Linux's advancing PID allocation so a just-reaped
 * number is not immediately reassigned to an unrelated job. */
int main(void) {
    for (unsigned round = 0; round < 32; ++round) {
        pid_t retired = fork(); assert(retired >= 0);
        if (!retired) { assert(setsid() == getpid()); _exit(0); }
        int status;
        assert(waitpid(retired, &status, 0) == retired && status == 0);
        int ready[2], hold[2]; assert(pipe(ready) == 0 && pipe(hold) == 0);
        pid_t unrelated = fork(); assert(unrelated >= 0);
        if (!unrelated) {
            assert(setsid() == getpid());
            assert(write(ready[1], "x", 1) == 1);
            char byte;
            _exit(read(hold[0], &byte, 1) == 1 ? 7 : 8);
        }
        char byte; assert(read(ready[0], &byte, 1) == 1);
        int cleaned = kill(-retired, SIGKILL), error = errno;
        if (cleaned != -1 || error != ESRCH) {
            fprintf(stderr, "PID_CLEANUP_FAIL retired=%d unrelated=%d cleanup=%d errno=%d\n",
                    retired, unrelated, cleaned, error);
            kill(unrelated, SIGKILL); waitpid(unrelated, &status, 0);
            return 1;
        }
        assert(kill(unrelated, 0) == 0);
        assert(write(hold[1], "x", 1) == 1);
        assert(waitpid(unrelated, &status, 0) == unrelated);
        assert(WIFEXITED(status) && WEXITSTATUS(status) == 7);
        close(ready[0]); close(ready[1]); close(hold[0]); close(hold[1]);
    }
    fprintf(stderr, "PID_CLEANUP_PASS: reaped-group cleanup preserves unrelated jobs\n");
    return 0;
}
