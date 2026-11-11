/* A double-forked helper must never become DN's child and steal its focus. */
#include <assert.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void) {
    int report[2];
    assert(pipe(report) == 0);
    pid_t middle = fork();
    assert(middle >= 0);
    if (!middle) {
        close(report[0]);
        pid_t parent = getpid(), leaf = fork();
        assert(leaf >= 0);
        if (leaf) _exit(0);
        for (int attempt = 0; attempt < 1000 && getppid() == parent; ++attempt)
            usleep(1000);
        pid_t adopter = getppid();
        assert(adopter != parent);
        assert(write(report[1], &adopter, sizeof adopter) == sizeof adopter);
        _exit(0);
    }
    close(report[1]);
    int status;
    assert(waitpid(middle, &status, 0) == middle && status == 0);
    pid_t adopter;
    assert(read(report[0], &adopter, sizeof adopter) == sizeof adopter);
    assert(adopter > 1);
    close(report[0]);
    usleep(50000);
    puts("ORPHAN_CONSOLE_PASS");
    return 0;
}
