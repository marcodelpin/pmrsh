/* sys_cosmo.h — Cosmopolitan libc (APE) platform layer
 * Included by sys.h when __COSMOPOLITAN__ is defined.
 * Uses standard POSIX API — cosmocc maps to all platforms.
 */
#ifndef PMASH_SYS_COSMO_H
#define PMASH_SYS_COSMO_H

#include <cosmo.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <signal.h>
#include <poll.h>
#include <string.h>
#include <stdlib.h>

/* Syscall number constants — used as dispatch keys by sys() wrappers below */
#define SYS_READ     0
#define SYS_WRITE    1
#define SYS_OPEN     2
#define SYS_CLOSE    3
#define SYS_LSEEK    8
#define SYS_BRK      12
#define SYS_NANOSLEEP 35
#define SYS_GETPID   39
#define SYS_MKDIR    83
#define SYS_UNLINK   87
#define SYS_RENAME   82
#define SYS_FORK     57
#define SYS_SETSID   112
#define SYS_KILL     62
#define SYS_READLINK 89
#define SYS_SENDTO   44
#define SYS_RECVFROM 45
#define SYS_GETRANDOM 318
#define SYS_POLL     7
#define SYS_SOCKET   41
#define SYS_CONNECT  42
#define SYS_ACCEPT   43
#define SYS_BIND     49
#define SYS_LISTEN   50
#define SYS_SETSOCKOPT 54
#define SYS_FSTAT    5
#define SYS_PIPE     22
#define SYS_DUP2     33
#define SYS_WAIT4    61
#define SYS_EXECVE   59
#define SYS_EXIT     60

/* sys() wrappers — dispatch to POSIX based on syscall number.
 * This lets code like sys2(SYS_MKDIR, path, mode) work on cosmo. */

static inline long sys1(long nr, long a) {
    if (nr == SYS_EXIT) _exit((int)a);
    if (nr == SYS_SETSID) return setsid();
    if (nr == SYS_UNLINK) return unlink((const char*)a);
    if (nr == SYS_FORK) return fork();
    if (nr == 3/*CLOSE*/) return close((int)a);
    return -1;
}
static inline long sys2(long nr, long a, long b) {
    if (nr == SYS_MKDIR) return mkdir((const char*)a, (int)b);
    if (nr == SYS_RENAME) return rename((const char*)a, (const char*)b);
    if (nr == SYS_KILL) return kill((int)a, (int)b);
    if (nr == SYS_DUP2) return dup2((int)a, (int)b);
    if (nr == SYS_LISTEN) return listen((int)a, (int)b);
    if (nr == SYS_FSTAT) { return fstat((int)a, (struct stat*)b); }
    if (nr == 35/*NANOSLEEP*/) { struct timespec *ts = (void*)a; return nanosleep(ts, 0); }
    return -1;
}
static inline long sys3(long nr, long a, long b, long c) {
    if (nr == 0/*READ*/) return read((int)a, (void*)b, (size_t)c);
    if (nr == 1/*WRITE*/) return write((int)a, (const void*)b, (size_t)c);
    if (nr == 2/*OPEN*/) return open((const char*)a, (int)b, (int)c);
    if (nr == SYS_SOCKET) return socket((int)a, (int)b, (int)c);
    if (nr == SYS_CONNECT) return connect((int)a, (const struct sockaddr*)b, (int)c);
    if (nr == SYS_ACCEPT) return accept((int)a, (struct sockaddr*)b, (int*)c);
    if (nr == SYS_BIND) return bind((int)a, (const struct sockaddr*)b, (int)c);
    if (nr == SYS_POLL) return poll((struct pollfd*)a, (unsigned)b, (int)c);
    if (nr == SYS_READLINK) return readlink((const char*)a, (char*)b, (size_t)c);
    if (nr == SYS_EXECVE) return execve((const char*)a, (char**)b, (char**)c);
    if (nr == SYS_GETRANDOM) return getentropy((void*)a, (size_t)b) == 0 ? (long)b : -1;
    if (nr == SYS_PIPE) return pipe((int*)a);
    return -1;
}
static inline long sys4(long nr, long a, long b, long c, long d) {
    if (nr == SYS_WAIT4) return waitpid((int)a, (int*)b, (int)c);
    return -1;
}
static inline long sys5(long nr, long a, long b, long c, long d, long e) {
    if (nr == SYS_SETSOCKOPT) return setsockopt((int)a, (int)b, (int)c, (const void*)d, (int)e);
    return -1;
}
static inline long sys6(long nr, long a, long b, long c, long d, long e, long f) {
    if (nr == SYS_SENDTO) return sendto((int)a, (const void*)b, (size_t)c, (int)d, (const struct sockaddr*)e, (int)f);
    if (nr == SYS_RECVFROM) return recvfrom((int)a, (void*)b, (size_t)c, (int)d, (struct sockaddr*)e, (socklen_t*)f);
    return -1;
}

/* I/O wrappers — use POSIX directly */

static inline ssize_t io_write(int fd, const void *buf, size_t len) {
    return write(fd, buf, len);
}
static inline ssize_t io_read(int fd, void *buf, size_t len) {
    return read(fd, buf, len);
}
static inline int io_open(const char *path, int flags) {
    if (flags == 1) return open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    return open(path, O_RDONLY);
}
static inline int io_close(int fd) { return close(fd); }
static inline long io_seek(int fd, long off, int whence) {
    return (long)lseek(fd, off, whence);
}
static inline void io_exit(int code) { _exit(code); __builtin_unreachable(); }
static inline long io_filesize(int fd) {
    struct stat st;
    if (fstat(fd, &st) < 0) return -1;
    return st.st_size;
}
static inline void io_print(int fd, const char *s) {
    write(fd, s, strlen(s));
}
static inline int net_socket(void) {
    return socket(AF_INET, SOCK_STREAM, 0);
}
static inline int net_connect(int fd, uint32_t ip, uint16_t port) {
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = ip;
    return connect(fd, (struct sockaddr*)&sa, sizeof(sa));
}
static inline int net_bind(int fd, uint16_t port) {
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    return bind(fd, (struct sockaddr*)&sa, sizeof(sa));
}
static inline int net_listen(int fd, int backlog) {
    return listen(fd, backlog);
}
static inline int net_accept(int fd) {
    return accept(fd, 0, 0);
}

#endif /* PMASH_SYS_COSMO_H */
