#define _GNU_SOURCE
#include <assert.h>
#include <cpuid.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sched.h>
#include <unistd.h>
#include <time.h>

#define CHILDREN 16
struct state { volatile unsigned start; volatile unsigned cpu[CHILDREN], end_cpu[CHILDREN]; volatile uint64_t result[CHILDREN]; };
static unsigned cpu(void) { unsigned a,b,c,d; __cpuid(1,a,b,c,d); return b >> 24; }
int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "vfork-child")) return 37;
    unsigned expected = argc > 1 ? atoi(argv[1]) : 1;
    int fd = open("/shared", O_CREAT|O_RDWR|O_TRUNC, 0600); assert(fd >= 0);
    assert(ftruncate(fd, 4096) == 0);
    struct state *s = mmap(0, 4096, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0); assert(s != MAP_FAILED);
    int counter = eventfd(0, EFD_NONBLOCK); assert(counter >= 0);
    int packets[2]; assert(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0, packets) == 0);
    int ep = epoll_create1(0); assert(ep >= 0);
    struct epoll_event watched = {.events=EPOLLIN, .data.u64=0x1234};
    assert(epoll_ctl(ep, EPOLL_CTL_ADD, packets[0], &watched) == 0);
    volatile unsigned private_value = 17;
    volatile unsigned char *high = mmap((void *)(1ULL<<40), 2*1024*1024,
        PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED_NOREPLACE, -1, 0);
    assert(high == (void *)(1ULL<<40));
    for (unsigned n=0; n<2*1024*1024; n+=4096) high[n] = 17;
    for (unsigned i=0; i<CHILDREN; ++i) {
        pid_t child = fork(); assert(child >= 0);
        if (!child) {
            while (!s->start) __asm__ volatile("pause");
            s->cpu[i] = cpu();
            uint64_t x = 0x12345678 + i;
            for (unsigned n=0; n<12000000; ++n) { x = x*6364136223846793005ULL+1; x ^= x>>21; }
            private_value = 100+i;
            for (unsigned n=0; n<2*1024*1024; n+=4096) { assert(high[n] == 17); high[n] = 100+i; }
            for (unsigned n=0; n<2*1024*1024; n+=4096) assert(high[n] == 100+i);
            s->result[i] = x;
            s->end_cpu[i] = cpu();
            unsigned reported = 999;
            assert(syscall(SYS_getcpu, &reported, 0, 0) == 0 && reported == s->cpu[i]);
            char proc[256];int identity=-1;
            int own=open("/proc/self/stat",O_RDONLY);assert(own>=0);
            int n=read(own,proc,sizeof(proc)-1);assert(n>0);proc[n]=0;
            assert(sscanf(proc,"%d",&identity)==1 && identity==getpid());close(own);
            for (unsigned n=0; n<128; ++n) assert(eventfd_write(counter, 1) == 0);
            for (unsigned n=0; n<4; ++n) {
                unsigned packet = i*4+n;
                assert(write(packets[1], &packet, sizeof(packet)) == sizeof(packet));
            }
            if (i == 0) {
                struct epoll_event changed = {.events=EPOLLIN, .data.u64=0x5678};
                assert(epoll_ctl(ep, EPOLL_CTL_MOD, packets[0], &changed) == 0);
            }
            // Saturate pinned CPUs while vfork children inherit their parent's
            // CPU. A queued child must never retain an unassigned CPU index.
            for (unsigned n=0; n<4; ++n) {
                char *args[] = {"probe", "vfork-child", NULL};
                pid_t spawned = vfork(); assert(spawned >= 0);
                if (!spawned) { execv("/probe", args); _exit(127); }
                int status;
                assert(waitpid(spawned, &status, 0) == spawned);
                assert(WIFEXITED(status) && WEXITSTATUS(status) == 37);
            }
            _exit(private_value != 100+i);
        }
    }
    struct timespec begin, end;
    assert(clock_gettime(CLOCK_MONOTONIC, &begin) == 0);
    s->start = 1;
    for (unsigned i=0; i<CHILDREN; ++i) { int status; assert(wait(&status)>0 && WIFEXITED(status) && WEXITSTATUS(status)==0); }
    assert(clock_gettime(CLOCK_MONOTONIC, &end) == 0);
    eventfd_t total; assert(eventfd_read(counter, &total) == 0 && total == CHILDREN*128);
    assert(epoll_wait(ep, &watched, 1, 0) == 1 && watched.data.u64 == 0x5678);
    unsigned received[CHILDREN*4] = {0};
    for (unsigned n=0; n<CHILDREN*4; ++n) {
        unsigned packet;
        assert(read(packets[0], &packet, sizeof(packet)) == sizeof(packet));
        assert(packet < CHILDREN*4 && received[packet]++ == 0);
    }
    assert(epoll_wait(ep, &watched, 1, 0) == 0);
    close(ep); close(counter); close(packets[0]); close(packets[1]);
    assert(private_value == 17);
    for (unsigned n=0; n<2*1024*1024; n+=4096) assert(high[n] == 17);
    fprintf(stderr, "PARALLEL_WORK_NS %llu\n", (unsigned long long)
        ((end.tv_sec-begin.tv_sec)*1000000000LL + end.tv_nsec-begin.tv_nsec));
    unsigned seen[256]={0}, count=0;
    for (unsigned i=0; i<CHILDREN; ++i) {
        assert(s->result[i] != 0 && s->cpu[i] == s->end_cpu[i]);
        if (!seen[s->cpu[i]]) { seen[s->cpu[i]]=1; ++count; }
    }
    fprintf(stderr,"PARALLEL_CPUS count=%u ids=",count);
    for (unsigned i=0;i<256;++i) if(seen[i]) fprintf(stderr,"%u,",i);
    fprintf(stderr,"\n");
    assert(count >= expected);
    /* Waiters pinned to APs must publish deferred wait status before resume. */
    for (unsigned i=0; i<8; ++i) {
        pid_t child = fork(); assert(child >= 0);
        if (!child) {
            pid_t grandchild = fork(); assert(grandchild >= 0);
            if (!grandchild) _exit(37);
            int status = -1;
            assert(waitpid(grandchild, &status, 0) == grandchild);
            assert(WIFEXITED(status) && WEXITSTATUS(status) == 37);
            _exit(0);
        }
    }
    for (unsigned i=0; i<8; ++i) {
        int status; assert(wait(&status)>0 && WIFEXITED(status) && WEXITSTATUS(status)==0);
    }
    fprintf(stderr,"PARALLEL_PROCESS_PASS pinned=1 cow=1 wait_status=1 shared_descriptors=1 queued_vfork=1 children=%u\n",CHILDREN);
    return 0;
}
