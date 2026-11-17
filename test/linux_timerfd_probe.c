/* timerfd: arming, reading, epoll (including Netty's edge-triggered re-arm
   without read), periodic overruns, blocking read and the error surface. */
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <time.h>
#include <unistd.h>

#define CHECK(ok) do { if (!(ok)) { dprintf(2, "TIMERFD_FAIL line=%d errno=%d\n", __LINE__, errno); _exit(1); } } while (0)
#define MS 1000000L

static long now_ms(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1000 + t.tv_nsec / MS;
}
static void arm(int fd, long value_ns, long interval_ns) {
    struct itimerspec spec = { { 0, interval_ns }, { 0, value_ns } };
    CHECK(timerfd_settime(fd, 0, &spec, NULL) == 0);
}
static int wait_one(int ep, int timeout) {
    struct epoll_event event;
    return epoll_wait(ep, &event, 1, timeout);
}

int main(void) {
    uint64_t count;
    errno = 0; CHECK(timerfd_create(CLOCK_PROCESS_CPUTIME_ID, 0) == -1 && errno == EINVAL);
    errno = 0; CHECK(timerfd_create(CLOCK_MONOTONIC, 4) == -1 && errno == EINVAL);

    int fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    CHECK(fd >= 0);
    char link[64] = {0}, path[64];
    snprintf(path, sizeof path, "/proc/self/fd/%d", fd);
    CHECK(readlink(path, link, sizeof link - 1) > 0 && strcmp(link, "anon_inode:[timerfd]") == 0);
    errno = 0; CHECK(read(fd, &count, 8) == -1 && errno == EAGAIN);
    errno = 0; CHECK(read(fd, &count, 4) == -1 && errno == EINVAL);
    errno = 0; CHECK(write(fd, &count, 8) == -1 && errno == EINVAL);

    /* One-shot through edge-triggered epoll, then disarmed. */
    int ep = epoll_create1(EPOLL_CLOEXEC);
    struct epoll_event watch = { .events = EPOLLIN | EPOLLET, .data.u64 = 7 };
    CHECK(epoll_ctl(ep, EPOLL_CTL_ADD, fd, &watch) == 0);
    long start = now_ms();
    arm(fd, 20 * MS, 0);
    CHECK(wait_one(ep, 2000) == 1);
    CHECK(now_ms() - start >= 18);
    CHECK(read(fd, &count, 8) == 8 && count == 1);
    struct itimerspec current;
    CHECK(timerfd_gettime(fd, &current) == 0 && current.it_value.tv_sec == 0 && current.it_value.tv_nsec == 0);

    /* Netty: fire, never read, re-arm, and expect a fresh edge each time. */
    for (int i = 0; i < 3; i++) {
        arm(fd, 10 * MS, 0);
        CHECK(wait_one(ep, 2000) == 1);
    }
    CHECK(read(fd, &count, 8) == 8 && count == 1); /* re-arming discarded the older expirations */

    /* Periodic: unread, it raises one edge (Linux restarts the timer only on
       read); the overruns still accumulate, and a read starts a new edge. */
    arm(fd, 5 * MS, 5 * MS);
    CHECK(wait_one(ep, 2000) == 1);
    CHECK(wait_one(ep, 30) == 0);
    CHECK(read(fd, &count, 8) == 8 && count >= 6);
    CHECK(wait_one(ep, 2000) == 1);
    CHECK(timerfd_gettime(fd, &current) == 0 && current.it_interval.tv_nsec == 5 * MS
          && current.it_value.tv_sec == 0 && current.it_value.tv_nsec > 0 && current.it_value.tv_nsec <= 5 * MS);

    /* Re-arming reports the old setting; zero disarms. */
    struct itimerspec off = {0}, old;
    CHECK(timerfd_settime(fd, 0, &off, &old) == 0 && old.it_interval.tv_nsec == 5 * MS);
    usleep(20000);
    errno = 0; CHECK(read(fd, &count, 8) == -1 && errno == EAGAIN);

    /* poll() sees an expired timer. */
    arm(fd, 1 * MS, 0);
    struct pollfd p = { .fd = fd, .events = POLLIN };
    CHECK(poll(&p, 1, 2000) == 1 && (p.revents & POLLIN));

    /* Blocking read on an absolute CLOCK_MONOTONIC deadline. */
    int blocking = timerfd_create(CLOCK_MONOTONIC, 0);
    CHECK(blocking >= 0);
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    t.tv_nsec += 25 * MS; if (t.tv_nsec >= 1000 * MS) { t.tv_sec++; t.tv_nsec -= 1000 * MS; }
    struct itimerspec absolute = { { 0, 0 }, t };
    start = now_ms();
    CHECK(timerfd_settime(blocking, TFD_TIMER_ABSTIME, &absolute, NULL) == 0);
    CHECK(read(blocking, &count, 8) == 8 && count == 1);
    CHECK(now_ms() - start >= 20);

    /* settime/gettime on the wrong kind of descriptor. */
    int event = eventfd(0, 0);
    errno = 0; CHECK(timerfd_settime(event, 0, &off, NULL) == -1 && errno == EINVAL);
    errno = 0; CHECK(timerfd_gettime(0, &current) == -1 && errno == EINVAL);
    errno = 0; CHECK(timerfd_gettime(987, &current) == -1 && errno == EBADF);
    errno = 0; CHECK(timerfd_settime(fd, 4, &off, NULL) == -1 && errno == EINVAL);

    close(event); close(blocking); close(ep); close(fd);
    dprintf(2, "TIMERFD_PASS: one-shot, ET re-arm, periodic overruns, gettime, poll, blocking abstime read, errors\n");
    return 0;
}
