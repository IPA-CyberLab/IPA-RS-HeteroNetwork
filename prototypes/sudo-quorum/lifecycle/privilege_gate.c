/* Linux-only sudo privilege gate. No execution, HTTP, signatures, or environment trust. */
#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sudo_plugin.h>

static sudo_printf_t report;
static uid_t caller;
static int initialized;

static int valid_fields(char * const entries[])
{
    if (entries == NULL) return 0;
    for (size_t i = 0; i < 512; i++) {
        if (entries[i] == NULL) return 1;
        size_t length = strnlen(entries[i], 65537);
        if (length > 65536) return 0;
        const char *equals = memchr(entries[i], '=', length);
        if (equals == NULL || equals == entries[i]) return 0;
        size_t n = (size_t)(equals - entries[i]);
        for (size_t j = 0; j < i; j++) {
            const char *previous = strchr(entries[j], '=');
            if (previous != NULL && (size_t)(previous - entries[j]) == n
                && memcmp(entries[i], entries[j], n) == 0) return 0;
        }
    }
    return 0;
}

static const char *field(char * const entries[], const char *name)
{
    const char *found = NULL;
    size_t n = strlen(name);
    if (entries == NULL) return NULL;
    for (size_t i = 0; i < 512; i++) {
        if (entries[i] == NULL) return found;
        size_t length = strnlen(entries[i], 65537);
        if (length > 65536) return NULL;
        if (length > n && memcmp(entries[i], name, n) == 0 && entries[i][n] == '=') {
            if (found != NULL) return NULL;
            found = entries[i] + n + 1;
        }
    }
    return NULL;
}

static int number(const char *value, uint32_t *out)
{
    if (value == NULL || *value == '\0' || strlen(value) > 10) return 0;
    for (const char *p = value; *p; p++) if (*p < '0' || *p > '9') return 0;
    char *end;
    errno = 0;
    unsigned long n = strtoul(value, &end, 10);
    if (errno || *end || n > UINT32_MAX) return 0;
    *out = (uint32_t)n;
    return 1;
}

static int gate_open(unsigned int version, sudo_conv_t conversation,
    sudo_printf_t plugin_printf, char * const settings[], char * const user_info[],
    int submit_optind, char * const submit_argv[], char * const submit_envp[],
    char * const plugin_options[], const char **errstr)
{
    (void)conversation; (void)settings; (void)submit_optind; (void)submit_argv;
    (void)submit_envp; (void)plugin_options; (void)errstr;
    initialized = 0;
    uint32_t uid;
    if (version != SUDO_API_VERSION || plugin_printf == NULL || geteuid() != 0 || !valid_fields(user_info)
        || !number(field(user_info, "uid"), &uid) || uid != getuid() || uid == 0)
        return -1; /* Zero would disable this gate. */
    caller = uid;
    report = plugin_printf;
    initialized = 1;
    return 1;
}

static int trusted(const char *path, int socket_path)
{
    struct stat st;
    return lstat(path, &st) == 0 && st.st_uid == 0 && (st.st_mode & 0022) == 0
        && (socket_path ? S_ISSOCK(st.st_mode) && (st.st_mode & 0777) == 0600 : S_ISDIR(st.st_mode));
}

static int64_t milliseconds(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) return -1;
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

static int ready(int fd, short events, int64_t deadline)
{
    for (;;) {
        int64_t now = milliseconds();
        if (now < 0 || now >= deadline) return 0;
        struct pollfd p = { .fd = fd, .events = events };
        int rc = poll(&p, 1, (int)(deadline - now));
        if (rc < 0 && errno == EINTR) continue;
        return rc == 1 && (p.revents & events) != 0;
    }
}

static int transfer(int fd, unsigned char *bytes, size_t n, int writing, int64_t deadline)
{
    while (n) {
        if (!ready(fd, writing ? POLLOUT : POLLIN, deadline)) return 0;
        ssize_t count = writing ? send(fd, bytes, n, MSG_NOSIGNAL) : recv(fd, bytes, n, 0);
        if (count < 0 && (errno == EINTR || errno == EAGAIN)) continue;
        if (count <= 0) return 0;
        bytes += count;
        n -= (size_t)count;
    }
    return 1;
}

static int approve(void)
{
    const char *path = "/run/ipars-sudo-prototype/adapter.sock";
    if (!trusted("/", 0) || !trusted("/run", 0) || !trusted("/run/ipars-sudo-prototype", 0) || !trusted(path, 1)) return 0;
    int64_t start = milliseconds();
    if (start < 0) return 0;
    int64_t deadline = start + 65000;
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) return 0;
    int result = 0;
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    memcpy(addr.sun_path, path, strlen(path) + 1);
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        if (errno != EINPROGRESS || !ready(fd, POLLOUT, deadline)) goto done;
        int error;
        socklen_t size = sizeof(error);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) != 0 || error != 0) goto done;
    }
    struct ucred peer;
    socklen_t size = sizeof(peer);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &size) != 0 || size != sizeof(peer) || peer.uid != 0) goto done;
    unsigned char request[8] = { 'S', 'Q', 'P', '1', caller >> 24, caller >> 16, caller >> 8, caller };
    unsigned char nonce[32];
    if (!transfer(fd, request, sizeof(request), 1, deadline) || !transfer(fd, nonce, sizeof(nonce), 0, deadline)) goto done;
    char handle[65];
    for (size_t i = 0; i < sizeof(nonce); i++) snprintf(handle + i * 2, 3, "%02x", nonce[i]);
    if (report(SUDO_CONV_INFO_MSG, "sudo privilege approval handle: %s\n", handle) < 0) goto done;
    if (fflush(stdout) != 0) goto done;
    unsigned char accepted;
    if (transfer(fd, &accepted, 1, 0, deadline) && accepted == 1) result = 1;
done:
    close(fd);
    return result;
}

static int gate_check(char * const info[], char * const argv[], char * const env[], const char **errstr)
{
    (void)argv; (void)env;
    uint32_t uid, euid;
    const char *edit = field(info, "sudoedit");
    const char *effective = field(info, "runas_euid");
    int allowed = initialized && valid_fields(info) && caller == getuid() && geteuid() == 0
        && number(field(info, "runas_uid"), &uid) && uid == 0
        && (effective == NULL || (number(effective, &euid) && euid == 0))
        && (edit == NULL || strcmp(edit, "false") == 0);
    initialized = 0; /* One adapter invocation only. */
    if (allowed && approve()) return 1;
    if (errstr != NULL) *errstr = "single-use sudo privilege grant required or unavailable";
    if (report != NULL) report(SUDO_CONV_ERROR_MSG, "%s\n", "single-use sudo privilege grant required or unavailable");
    return 0;
}

struct approval_plugin quorum_privilege_gate = {
    .type = SUDO_APPROVAL_PLUGIN,
    .version = SUDO_API_VERSION,
    .open = gate_open,
    .check = gate_check,
};
