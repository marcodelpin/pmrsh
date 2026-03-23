/* util.c — String, memory, I/O utilities */
#include "sys.h"

size_t pm_strlen(const char *s) {
    size_t n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

void *pm_memcpy(void *d, const void *s, size_t n) {
    char *dd = d; const char *ss = s;
    while (n--) *dd++ = *ss++;
    return d;
}

void *pm_memset(void *d, int c, size_t n) {
    char *dd = d;
    while (n--) *dd++ = (char)c;
    return d;
}

int pm_memcmp(const void *a, const void *b, size_t n) {
    const unsigned char *aa = a, *bb = b;
    while (n--) { if (*aa != *bb) return *aa - *bb; aa++; bb++; }
    return 0;
}

int pm_strcmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

int pm_atoi(const char *s) {
    int r = 0, neg = 0;
    if (*s == '-') { neg = 1; s++; }
    while (*s >= '0' && *s <= '9') r = r * 10 + (*s++ - '0');
    return neg ? -r : r;
}

int io_hostname(char *buf, int len) {
    int fd = io_open("/etc/hostname", 0);
    if (fd < 0) return 0;
    int r = io_read(fd, buf, len);
    io_close(fd);
    if (r > 0) { buf[r-1] = 0; return r-1; }
    return 0;
}

void io_sleep_ms(int ms) {
    long ts[2] = { ms / 1000, (ms % 1000) * 1000000L };
    sys2(SYS_NANOSLEEP, (long)ts, 0);
}

int io_exec(const char *cmd, char *outbuf, int outbufsize) {
    int pipefd[2];
    if (sys1(SYS_PIPE, (long)pipefd) < 0) return -1;
    long pid = sys1(SYS_FORK, 0);
    if (pid < 0) { io_close(pipefd[0]); io_close(pipefd[1]); return -1; }
    if (pid == 0) {
        io_close(pipefd[0]);
        sys2(SYS_DUP2, pipefd[1], 1);
        sys2(SYS_DUP2, pipefd[1], 2);
        io_close(pipefd[1]);
        const char *argv[] = { "/bin/sh", "-c", cmd, 0 };
        sys3(SYS_EXECVE, (long)"/bin/sh", (long)argv, 0);
        io_exit(127);
    }
    io_close(pipefd[1]);
    int total = 0, timeout = 300;
    while (timeout > 0) {
        struct { int fd; short events, revents; } pfd = { pipefd[0], POLLIN, 0 };
        long pr = sys3(SYS_POLL, (long)&pfd, 1, 100);
        if (pr > 0) {
            ssize_t r = io_read(pipefd[0], outbuf + total, outbufsize - total);
            if (r <= 0) break;
            total += r;
            timeout = 300;
        } else timeout--;
    }
    if (timeout <= 0) sys2(SYS_KILL, pid, SIGKILL);
    io_close(pipefd[0]);
    sys4(SYS_WAIT4, pid, 0, 0, 0);
    outbuf[total] = 0;
    return total;
}

uint32_t parse_ip(const char *s) {
    uint32_t ip = 0; int octet = 0;
    for (; *s; s++) {
        if (*s == '.') { ip = (ip << 8) | octet; octet = 0; }
        else octet = octet * 10 + (*s - '0');
    }
    ip = (ip << 8) | octet;
    return __builtin_bswap32(ip);
}
