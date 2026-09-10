/* Deterministic clocks exercise buffered ACKs without changing the host clock. */
#define _GNU_SOURCE
#include <sys/socket.h>
#include <time.h>
#include <assert.h>
#include <stdint.h>
#include <unistd.h>

static int64_t mono = 1000;
static time_t wall = 100;
static int fail_clock;
static int delay_read;
static int fake_clock_gettime(clockid_t id, struct timespec *t)
{
    if (fail_clock) return -1;
    t->tv_sec = id == CLOCK_REALTIME ? wall : mono / 1000;
    t->tv_nsec = id == CLOCK_REALTIME ? 0 : (mono % 1000) * 1000000;
    return 0;
}
static ssize_t delayed_recv(int fd, void *buf, size_t n, int flags)
{
    ssize_t count = recv(fd, buf, n, flags);
    if (delay_read) mono = 5000;
    return count;
}
#define clock_gettime fake_clock_gettime
#define recv delayed_recv
#include "privilege_v2_gate.c"

static int buffered_ack(int resume_expired)
{
    int fd[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0);
    unsigned char ack[9] = {1, 0, 0, 0, 0, 0, 0, 0, 101};
    assert(write(fd[0], ack, sizeof(ack)) == sizeof(ack));
    if (resume_expired) wall = 101;
    int result = accept_v2_ack(fd[1], 5000);
    close(fd[0]);
    close(fd[1]);
    return result;
}

int main(void)
{
    assert(buffered_ack(0));
    /* Already-buffered success must not admit a reader resumed at expiry. */
    assert(!buffered_ack(1));
    wall = 100;
    delay_read = 1;
    assert(!buffered_ack(0)); /* Last recv crosses monotonic deadline. */
    delay_read = 0;
    mono = 1000;
    fail_clock = 1;
    assert(!buffered_ack(0));
    return 0;
}
