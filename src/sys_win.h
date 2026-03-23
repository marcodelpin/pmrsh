/* sys_win.h — Windows implementations of I/O + network (WinSock2 + Win32 API)
 * Included by sys.h when _WIN32 is defined.
 * Replaces inline Linux syscalls with Win32 API calls.
 */
#ifndef PMASH_SYS_WIN_H
#define PMASH_SYS_WIN_H

/* Common constants needed by platform-independent code */
#define POLLIN       1
#define SEEK_SET     0
#define SIGKILL      9
#define AF_INET      2
#define SOCK_STREAM  1
#define SOCK_DGRAM   2
#define SOL_SOCKET   0xFFFF
#define SO_REUSEADDR 4
#define O_RDONLY     0
#define O_WRONLY     1
#define O_RDWR       2
#define O_CREAT      0x100
#define O_TRUNC      0x200

/* Stub syscall numbers — referenced by code but never called on Windows.
 * The actual Windows implementations use Win32 API, not syscall numbers. */
#define SYS_READ 0
#define SYS_WRITE 0
#define SYS_OPEN 0
#define SYS_CLOSE 0
#define SYS_LSEEK 0
#define SYS_BRK 0
#define SYS_NANOSLEEP 0
#define SYS_GETPID 0
#define SYS_MKDIR 0
#define SYS_UNLINK 0
#define SYS_RENAME 0
#define SYS_FORK 0
#define SYS_SETSID 0
#define SYS_KILL 0
#define SYS_READLINK 0
#define SYS_POLL 0
#define SYS_PIPE 0
#define SYS_DUP2 0
#define SYS_WAIT4 0
#define SYS_EXECVE 0
#define SYS_EXIT 0
#define SYS_SENDTO 0
#define SYS_RECVFROM 0
#define SYS_GETRANDOM 0
#define SYS_FSTAT 0
#define SYS_SOCKET 0
#define SYS_CONNECT 0
#define SYS_ACCEPT 0
#define SYS_BIND 0
#define SYS_LISTEN 0
#define SYS_SETSOCKOPT 0

/* Stub sys() calls — Windows code uses Win32 API instead */
static inline long sys1(long n,long a){(void)n;(void)a;return -1;}
static inline long sys2(long n,long a,long b){(void)n;(void)a;(void)b;return -1;}
static inline long sys3(long n,long a,long b,long c){(void)n;(void)a;(void)b;(void)c;return -1;}
static inline long sys4(long n,long a,long b,long c,long d){(void)n;(void)a;(void)b;(void)c;(void)d;return -1;}
static inline long sys5(long n,long a,long b,long c,long d,long e){(void)n;(void)a;(void)b;(void)c;(void)d;(void)e;return -1;}
static inline long sys6(long n,long a,long b,long c,long d,long e,long f){(void)n;(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;return -1;}

/* Win32 API — use MinGW headers */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

/* === I/O wrappers (Windows) === */

static HANDLE hStdout, hStderr;
static int ws_init = 0;

static void win_init(void) {
    if (ws_init) return;
    ws_init = 1;
    hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
    hStderr = GetStdHandle(STD_ERROR_HANDLE);
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);
}

/* On Windows, fds < 0x10000 are likely sockets; stdout/stderr are handles.
 * This heuristic avoids needing separate socket send/recv paths. */
static inline ssize_t io_write(int fd, const void *buf, size_t len) {
    if (fd == 1) { DWORD w; WriteFile(hStdout, buf, (DWORD)len, &w, 0); return w; }
    if (fd == 2) { DWORD w; WriteFile(hStderr, buf, (DWORD)len, &w, 0); return w; }
    /* Try send() first (works for sockets), fall back to WriteFile */
    int r = send((SOCKET)(unsigned)fd, buf, (int)len, 0);
    if (r != SOCKET_ERROR) return r;
    DWORD w; WriteFile((HANDLE)(long long)fd, buf, (DWORD)len, &w, 0); return w;
}

static inline ssize_t io_read(int fd, void *buf, size_t len) {
    int r = recv((SOCKET)(unsigned)fd, buf, (int)len, 0);
    if (r != SOCKET_ERROR) return r;
    DWORD n; ReadFile((HANDLE)(long long)fd, buf, (DWORD)len, &n, 0); return n;
}

static inline int io_open(const char *path, int flags) {
    DWORD access = (flags == 0) ? GENERIC_READ : (GENERIC_READ | GENERIC_WRITE);
    DWORD disp = (flags == 0) ? OPEN_EXISTING : CREATE_ALWAYS;
    HANDLE h = CreateFileA(path, access, 0, 0, disp, FILE_ATTRIBUTE_NORMAL, 0);
    return (h == INVALID_HANDLE_VALUE) ? -1 : (int)(long long)h;
}

static inline int io_close(int fd) {
    CloseHandle((HANDLE)(long long)fd);
    return 0;
}

static inline long io_seek(int fd, long off, int whence) {
    return SetFilePointer((HANDLE)(long long)fd, off, 0, whence);
}

static inline void io_exit(int code) {
    ExitProcess(code);
    __builtin_unreachable();
}

static inline long io_filesize(int fd) {
    return GetFileSize((HANDLE)(long long)fd, 0);
}

static inline void io_print(int fd, const char *s) {
    size_t n = 0; while (s[n]) n++;
    io_write(fd, s, n);
}

static inline int net_socket(void) {
    win_init();
    return (int)socket(2/*AF_INET*/, 1/*SOCK_STREAM*/, 0);
}

static inline int net_connect(int fd, uint32_t ip, uint16_t port) {
    struct { uint16_t f; uint16_t p; uint32_t a; uint64_t z; } sa = {
        2, __builtin_bswap16(port), ip, 0
    };
    return connect((SOCKET)fd, (const struct sockaddr*)&sa, sizeof(sa));
}

static inline int net_bind(int fd, uint16_t port) {
    int one = 1;
    setsockopt((SOCKET)fd, 0xFFFF/*SOL_SOCKET*/, 4/*SO_REUSEADDR*/, (char*)&one, 4);
    struct { uint16_t f; uint16_t p; uint32_t a; uint64_t z; } sa = {
        2, __builtin_bswap16(port), 0, 0
    };
    return bind((SOCKET)fd, (const struct sockaddr*)&sa, sizeof(sa));
}

static inline int net_listen(int fd, int backlog) {
    return listen((SOCKET)fd, backlog);
}

static inline int net_accept(int fd) {
    return (int)accept((SOCKET)fd, 0, 0);
}

#endif /* PMASH_SYS_WIN_H */
