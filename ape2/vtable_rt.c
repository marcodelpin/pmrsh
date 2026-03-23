/* vtable_rt.c — Runtime OS vtable: single code, two OS backends
 *
 * NO #ifdefs. Both Linux and Windows implementations compiled together.
 * At startup: detect_os() → patch_vtable() fills function pointers.
 * All common code calls through vtable — zero OS-specific branches.
 *
 * Calling convention:
 *   All code compiled with SysV ABI (GCC default: rdi, rsi, rdx, rcx)
 *   Windows API calls go through ms_abi thunks that rearrange registers
 *
 * Compile: gcc -Os -fPIC -fno-plt -c vtable_rt.c
 */

/* Include shared header for types + vtable struct */
#include "sys_vtable.h"

/* Define the vtable instance (buffers defined by proto.c, server.c, sync.c) */
os_vtable_t vt;
int os_type;

/* === Pure utilities (no OS calls) === */
size_t pm_strlen(const char *s) { size_t n=0; if(!s) return 0; while(s[n]) n++; return n; }
void *pm_memcpy(void *d, const void *s, size_t n) { char *dd=d; const char *ss=s; while(n--) *dd++=*ss++; return d; }
void *pm_memset(void *d, int c, size_t n) { char *dd=d; while(n--) *dd++=(char)c; return d; }
int pm_memcmp(const void *a, const void *b, size_t n) { const unsigned char *aa=a,*bb=b; while(n--){if(*aa!=*bb)return *aa-*bb;aa++;bb++;} return 0; }
int pm_strcmp(const char *a, const char *b) { while(*a&&*a==*b){a++;b++;} return (unsigned char)*a-(unsigned char)*b; }
int pm_atoi(const char *s) { int r=0,neg=0; if(*s=='-'){neg=1;s++;} while(*s>='0'&&*s<='9') r=r*10+(*s++-'0'); return neg?-r:r; }
uint32_t parse_ip(const char *s) { uint32_t ip=0; int o=0; for(;*s;s++){if(*s=='.'){ip=(ip<<8)|o;o=0;}else o=o*10+(*s-'0');} ip=(ip<<8)|o; return __builtin_bswap32(ip); }

/* ========================================================================
 * LINUX IMPLEMENTATIONS — inline syscalls
 * ======================================================================== */

static __attribute__((always_inline)) long
lx_syscall1(long nr, long a) {
    long r;
    __asm__ volatile("syscall":"=a"(r):"a"(nr),"D"(a):"rcx","r11","memory");
    return r;
}
static __attribute__((always_inline)) long
lx_syscall2(long nr, long a, long b) {
    long r;
    __asm__ volatile("syscall":"=a"(r):"a"(nr),"D"(a),"S"(b):"rcx","r11","memory");
    return r;
}
static __attribute__((always_inline)) long
lx_syscall3(long nr, long a, long b, long c) {
    long r;
    register long r10 __asm__("r10") = 0;
    __asm__ volatile("syscall":"=a"(r):"a"(nr),"D"(a),"S"(b),"d"(c),"r"(r10):"rcx","r11","memory");
    return r;
}
static __attribute__((always_inline)) long
lx_syscall4(long nr, long a, long b, long c, long d) {
    long r;
    register long r10 __asm__("r10") = d;
    __asm__ volatile("syscall":"=a"(r):"a"(nr),"D"(a),"S"(b),"d"(c),"r"(r10):"rcx","r11","memory");
    return r;
}
static __attribute__((always_inline)) long
lx_syscall5(long nr, long a, long b, long c, long d, long e) {
    long r;
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    __asm__ volatile("syscall":"=a"(r):"a"(nr),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8):"rcx","r11","memory");
    return r;
}

/* Linux syscall numbers */
#define LX_READ     0
#define LX_WRITE    1
#define LX_OPEN     2
#define LX_CLOSE    3
#define LX_FSTAT    5
#define LX_POLL     7
#define LX_LSEEK    8
#define LX_PIPE     22
#define LX_DUP2     33
#define LX_NANOSLEEP 35
#define LX_GETPID   39
#define LX_SOCKET   41
#define LX_CONNECT  42
#define LX_ACCEPT   43
#define LX_BIND     49
#define LX_LISTEN   50
#define LX_SETSOCKOPT 54
#define LX_FORK     57
#define LX_EXECVE   59
#define LX_EXIT     60
#define LX_WAIT4    61
#define LX_KILL     62
#define LX_RENAME   82
#define LX_MKDIR    83
#define LX_UNLINK   87
#define LX_READLINK 89

static ssize_t lx_write(int fd, const void *buf, size_t len) {
    return lx_syscall3(LX_WRITE, fd, (long)buf, len);
}
static ssize_t lx_read(int fd, void *buf, size_t len) {
    return lx_syscall3(LX_READ, fd, (long)buf, len);
}
static int lx_open(const char *path, int flags) {
    int f = flags;
    if (f == 1) f = 1 | 64 | 512; /* O_WRONLY|O_CREAT|O_TRUNC */
    return (int)lx_syscall3(LX_OPEN, (long)path, f, 0644);
}
static int lx_close(int fd) { return (int)lx_syscall1(LX_CLOSE, fd); }
static long lx_seek(int fd, long off, int whence) {
    return lx_syscall3(LX_LSEEK, fd, off, whence);
}
static long lx_filesize(int fd) {
    char buf[144];
    if (lx_syscall2(LX_FSTAT, fd, (long)buf) < 0) return -1;
    return *(long*)(buf + 48);
}
static int lx_rename(const char *o, const char *n) {
    return (int)lx_syscall2(LX_RENAME, (long)o, (long)n);
}
static int lx_unlink(const char *p) { return (int)lx_syscall1(LX_UNLINK, (long)p); }
static int lx_mkdir(const char *p) { return (int)lx_syscall2(LX_MKDIR, (long)p, 0755); }
static int lx_socket(void) { return (int)lx_syscall3(LX_SOCKET, 2, 1, 0); }
static int lx_connect(int fd, uint32_t ip, uint16_t port) {
    struct { uint16_t f; uint16_t p; uint32_t a; uint64_t z; } sa = {
        2, (uint16_t)((port >> 8) | (port << 8)), ip, 0
    };
    return (int)lx_syscall3(LX_CONNECT, fd, (long)&sa, 16);
}
static int lx_bind(int fd, uint16_t port) {
    int one = 1;
    lx_syscall5(LX_SETSOCKOPT, fd, 1, 2, (long)&one, 4);
    struct { uint16_t f; uint16_t p; uint32_t a; uint64_t z; } sa = {
        2, (uint16_t)((port >> 8) | (port << 8)), 0, 0
    };
    return (int)lx_syscall3(LX_BIND, fd, (long)&sa, 16);
}
static int lx_listen(int fd, int backlog) {
    return (int)lx_syscall2(LX_LISTEN, fd, backlog);
}
static int lx_accept(int fd) {
    return (int)lx_syscall3(LX_ACCEPT, fd, 0, 0);
}
static int lx_send(int fd, const void *buf, size_t len) {
    return (int)lx_syscall3(LX_WRITE, fd, (long)buf, len);
}
static int lx_recv(int fd, void *buf, size_t len) {
    return (int)lx_syscall3(LX_READ, fd, (long)buf, len);
}
static void lx_exit(int code) {
    lx_syscall1(LX_EXIT, code);
    __builtin_unreachable();
}
static void lx_sleep_ms(int ms) {
    long ts[2] = { ms / 1000, (ms % 1000) * 1000000L };
    lx_syscall2(LX_NANOSLEEP, (long)ts, 0);
}
static int lx_hostname(char *buf, int len) {
    int fd = lx_open("/etc/hostname", 0);
    if (fd < 0) return 0;
    int r = lx_read(fd, buf, len);
    lx_close(fd);
    if (r > 0) { buf[r-1] = 0; return r-1; }
    return 0;
}
static int lx_getpid(void) { return (int)lx_syscall1(LX_GETPID, 0); }
static int lx_poll(int fd, int timeout_ms) {
    struct { int fd; short ev, rev; } pfd = { fd, 1/*POLLIN*/, 0 };
    return (int)lx_syscall3(LX_POLL, (long)&pfd, 1, timeout_ms);
}

static int lx_exec(const char *cmd, char *outbuf, int outbufsize) {
    int pipefd[2];
    if (lx_syscall1(LX_PIPE, (long)pipefd) < 0) return -1;
    long pid = lx_syscall1(LX_FORK, 0);
    if (pid < 0) { lx_close(pipefd[0]); lx_close(pipefd[1]); return -1; }
    if (pid == 0) {
        lx_close(pipefd[0]);
        lx_syscall2(LX_DUP2, pipefd[1], 1);
        lx_syscall2(LX_DUP2, pipefd[1], 2);
        lx_close(pipefd[1]);
        const char *argv[] = { "/bin/sh", "-c", cmd, 0 };
        lx_syscall3(LX_EXECVE, (long)"/bin/sh", (long)argv, 0);
        lx_exit(127);
    }
    lx_close(pipefd[1]);
    int total = 0, timeout = 300;
    while (timeout > 0) {
        int pr = lx_poll(pipefd[0], 100);
        if (pr > 0) {
            int r = lx_read(pipefd[0], outbuf + total, outbufsize - total);
            if (r <= 0) break;
            total += r;
            timeout = 300;
        } else timeout--;
    }
    if (timeout <= 0) lx_syscall2(LX_KILL, pid, 9);
    lx_close(pipefd[0]);
    lx_syscall4(LX_WAIT4, pid, 0, 0, 0);
    outbuf[total] = 0;
    return total;
}

/* ========================================================================
 * WINDOWS IMPLEMENTATIONS — NT syscalls via ms_abi thunks
 *
 * On Windows, we can't use int 0x80 or syscall instruction.
 * We need to call kernel32.dll / ws2_32.dll functions.
 * These are loaded via the PEB → LDR → module list → export table.
 *
 * Since we're compiled with SysV ABI, all Win32 calls need thunks
 * that rearrange registers: rdi/rsi/rdx/rcx → rcx/rdx/r8/r9
 * ======================================================================== */

/* Win32 API function pointers (resolved at startup from PEB) */
static void *win_kernel32;
static void *win_ws2_32;

/* ms_abi function pointer types for Win32 calls */
typedef long long __attribute__((ms_abi)) (*fn_WriteFile)(void*,const void*,uint32_t,uint32_t*,void*);
typedef long long __attribute__((ms_abi)) (*fn_ReadFile)(void*,void*,uint32_t,uint32_t*,void*);
typedef void* __attribute__((ms_abi)) (*fn_CreateFileA)(const char*,uint32_t,uint32_t,void*,uint32_t,uint32_t,void*);
typedef long long __attribute__((ms_abi)) (*fn_CloseHandle)(void*);
typedef void* __attribute__((ms_abi)) (*fn_GetStdHandle)(uint32_t);
typedef void __attribute__((ms_abi)) (*fn_ExitProcess)(uint32_t);
typedef void __attribute__((ms_abi)) (*fn_Sleep)(uint32_t);
typedef long long __attribute__((ms_abi)) (*fn_GetComputerNameA)(char*, uint32_t*);
typedef uint32_t __attribute__((ms_abi)) (*fn_GetFileSize)(void*, uint32_t*);
typedef uint32_t __attribute__((ms_abi)) (*fn_SetFilePointer)(void*, long, long*, uint32_t);
typedef long long __attribute__((ms_abi)) (*fn_MoveFileA)(const char*, const char*);
typedef long long __attribute__((ms_abi)) (*fn_DeleteFileA)(const char*);
typedef long long __attribute__((ms_abi)) (*fn_CreateDirectoryA)(const char*, void*);

/* WinSock */
typedef uint64_t __attribute__((ms_abi)) (*fn_socket)(int,int,int);
typedef int __attribute__((ms_abi)) (*fn_connect)(uint64_t,const void*,int);
typedef int __attribute__((ms_abi)) (*fn_bind)(uint64_t,const void*,int);
typedef int __attribute__((ms_abi)) (*fn_listen_)(uint64_t,int);
typedef uint64_t __attribute__((ms_abi)) (*fn_accept_)(uint64_t,void*,int*);
typedef int __attribute__((ms_abi)) (*fn_send_)(uint64_t,const char*,int,int);
typedef int __attribute__((ms_abi)) (*fn_recv_)(uint64_t,char*,int,int);
typedef int __attribute__((ms_abi)) (*fn_WSAStartup)(uint16_t, void*);
typedef int __attribute__((ms_abi)) (*fn_setsockopt_)(uint64_t,int,int,const char*,int);
typedef int __attribute__((ms_abi)) (*fn_closesocket_)(uint64_t);

/* Resolved function pointers */
static fn_WriteFile       pWriteFile;
static fn_ReadFile        pReadFile;
static fn_CreateFileA     pCreateFileA;
static fn_CloseHandle     pCloseHandle;
static fn_GetStdHandle    pGetStdHandle;
static fn_ExitProcess     pExitProcess;
static fn_Sleep           pSleep;
static fn_GetComputerNameA pGetComputerNameA;
static fn_GetFileSize     pGetFileSize;
static fn_SetFilePointer  pSetFilePointer;
static fn_MoveFileA       pMoveFileA;
static fn_DeleteFileA     pDeleteFileA;
static fn_CreateDirectoryA pCreateDirectoryA;
static fn_socket          pSocket;
static fn_connect         pConnect;
static fn_bind            pBind;
static fn_listen_         pListen;
static fn_accept_         pAccept;
static fn_send_           pSend;
static fn_recv_           pRecv;
static fn_WSAStartup      pWSAStartup;
static fn_setsockopt_     pSetsockopt;
static fn_closesocket_    pClosesocket;
static void *hStdout, *hStderr;

/* --- PEB-based module + export resolution (no LoadLibrary needed) --- */

/* Walk PEB → LDR → InMemoryOrderModuleList to find loaded DLLs */
static void *find_module(const char *name) {
    /* Read PEB from GS:[0x60] on x86_64 Windows */
    void *peb;
    __asm__("mov %%gs:0x60, %0" : "=r"(peb));
    /* PEB.Ldr at offset 0x18 */
    void *ldr = *(void**)((char*)peb + 0x18);
    /* LDR.InMemoryOrderModuleList at offset 0x20 */
    void *head = (char*)ldr + 0x20;
    void *entry = *(void**)head;
    while (entry != head) {
        /* Entry.BaseDllName at offset 0x40 (UNICODE_STRING: len, maxlen, buf) */
        uint16_t *uname = *(uint16_t**)((char*)entry + 0x40 + 8);
        uint16_t ulen = *(uint16_t*)((char*)entry + 0x40);
        /* Compare (case-insensitive, ASCII subset) */
        int match = 1;
        for (int i = 0; name[i]; i++) {
            if (i * 2 >= ulen) { match = 0; break; }
            char c1 = name[i]; if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
            char c2 = uname[i] & 0xFF; if (c2 >= 'A' && c2 <= 'Z') c2 += 32;
            if (c1 != c2) { match = 0; break; }
        }
        if (match) {
            /* Entry.DllBase at offset 0x20 */
            return *(void**)((char*)entry + 0x20);
        }
        entry = *(void**)entry; /* next entry */
    }
    return 0;
}

/* Resolve export by name from PE module */
static void *find_export(void *module, const char *name) {
    if (!module) return 0;
    char *base = module;
    /* PE header at offset from DOS header e_lfanew */
    uint32_t pe_off = *(uint32_t*)(base + 0x3C);
    char *pe = base + pe_off;
    /* Export directory RVA at PE+0x88 (64-bit) */
    uint32_t exp_rva = *(uint32_t*)(pe + 0x88);
    if (!exp_rva) return 0;
    char *exp = base + exp_rva;
    uint32_t num_names = *(uint32_t*)(exp + 0x18);
    uint32_t *names = (uint32_t*)(base + *(uint32_t*)(exp + 0x20));
    uint16_t *ords = (uint16_t*)(base + *(uint32_t*)(exp + 0x24));
    uint32_t *funcs = (uint32_t*)(base + *(uint32_t*)(exp + 0x1C));
    for (uint32_t i = 0; i < num_names; i++) {
        const char *ename = base + names[i];
        /* strcmp */
        const char *a = name, *b = ename;
        while (*a && *a == *b) { a++; b++; }
        if (*a == 0 && *b == 0) {
            return base + funcs[ords[i]];
        }
    }
    return 0;
}

static void win_resolve_apis(void) {
    win_kernel32 = find_module("kernel32.dll");
    pWriteFile = find_export(win_kernel32, "WriteFile");
    pReadFile = find_export(win_kernel32, "ReadFile");
    pCreateFileA = find_export(win_kernel32, "CreateFileA");
    pCloseHandle = find_export(win_kernel32, "CloseHandle");
    pGetStdHandle = find_export(win_kernel32, "GetStdHandle");
    pExitProcess = find_export(win_kernel32, "ExitProcess");
    pSleep = find_export(win_kernel32, "Sleep");
    pGetComputerNameA = find_export(win_kernel32, "GetComputerNameA");
    pGetFileSize = find_export(win_kernel32, "GetFileSize");
    pSetFilePointer = find_export(win_kernel32, "SetFilePointer");
    pMoveFileA = find_export(win_kernel32, "MoveFileA");
    pDeleteFileA = find_export(win_kernel32, "DeleteFileA");
    pCreateDirectoryA = find_export(win_kernel32, "CreateDirectoryA");
    hStdout = pGetStdHandle(-11);
    hStderr = pGetStdHandle(-12);

    /* Load ws2_32.dll via LoadLibraryA */
    void* __attribute__((ms_abi)) (*pLoadLibraryA)(const char*) =
        find_export(win_kernel32, "LoadLibraryA");
    if (pLoadLibraryA) {
        win_ws2_32 = pLoadLibraryA("ws2_32.dll");
        pSocket = find_export(win_ws2_32, "socket");
        pConnect = find_export(win_ws2_32, "connect");
        pBind = find_export(win_ws2_32, "bind");
        pListen = find_export(win_ws2_32, "listen");
        pAccept = find_export(win_ws2_32, "accept");
        pSend = find_export(win_ws2_32, "send");
        pRecv = find_export(win_ws2_32, "recv");
        pWSAStartup = find_export(win_ws2_32, "WSAStartup");
        pSetsockopt = find_export(win_ws2_32, "setsockopt");
        pClosesocket = find_export(win_ws2_32, "closesocket");
        /* Init WinSock */
        char wsadata[512];
        if (pWSAStartup) pWSAStartup(0x0202, wsadata);
    }
}

/* --- Windows vtable implementations (SysV ABI → ms_abi thunks) --- */

static ssize_t win_write(int fd, const void *buf, size_t len) {
    uint32_t written;
    void *h = (fd == 1) ? hStdout : (fd == 2) ? hStderr : (void*)(long long)fd;
    /* Try socket send first */
    if (pSend) {
        int r = pSend((uint64_t)(unsigned)fd, buf, (int)len, 0);
        if (r >= 0) return r;
    }
    pWriteFile(h, buf, (uint32_t)len, &written, 0);
    return written;
}
static ssize_t win_read(int fd, void *buf, size_t len) {
    if (pRecv) {
        int r = pRecv((uint64_t)(unsigned)fd, buf, (int)len, 0);
        if (r >= 0) return r;
    }
    uint32_t nread;
    pReadFile((void*)(long long)fd, buf, (uint32_t)len, &nread, 0);
    return nread;
}
static int win_open(const char *path, int flags) {
    uint32_t access = (flags == 0) ? 0x80000000 : 0xC0000000;
    uint32_t disp = (flags == 0) ? 3 : 2;
    void *h = pCreateFileA(path, access, 0, 0, disp, 0x80, 0);
    return (h == (void*)-1LL) ? -1 : (int)(long long)h;
}
static int win_close(int fd) { pCloseHandle((void*)(long long)fd); return 0; }
static long win_seek(int fd, long off, int whence) {
    return pSetFilePointer((void*)(long long)fd, off, 0, whence);
}
static long win_filesize(int fd) {
    return pGetFileSize((void*)(long long)fd, 0);
}
static int win_rename(const char *o, const char *n) {
    return pMoveFileA(o, n) ? 0 : -1;
}
static int win_unlink(const char *p) { return pDeleteFileA(p) ? 0 : -1; }
static int win_mkdir(const char *p) { return pCreateDirectoryA(p, 0) ? 0 : -1; }
static int win_socket(void) {
    return pSocket ? (int)pSocket(2, 1, 0) : -1;
}
static int win_connect(int fd, uint32_t ip, uint16_t port) {
    struct { uint16_t f; uint16_t p; uint32_t a; uint64_t z; } sa = {
        2, (uint16_t)((port >> 8) | (port << 8)), ip, 0
    };
    return pConnect ? pConnect((uint64_t)(unsigned)fd, &sa, 16) : -1;
}
static int win_bind(int fd, uint16_t port) {
    if (!pBind) return -1;
    int one = 1;
    if (pSetsockopt) pSetsockopt((uint64_t)(unsigned)fd, 0xFFFF, 4, (char*)&one, 4);
    struct { uint16_t f; uint16_t p; uint32_t a; uint64_t z; } sa = {
        2, (uint16_t)((port >> 8) | (port << 8)), 0, 0
    };
    return pBind((uint64_t)(unsigned)fd, &sa, 16);
}
static int win_listen(int fd, int backlog) {
    return pListen ? (int)pListen((uint64_t)(unsigned)fd, backlog) : -1;
}
static int win_accept(int fd) {
    return pAccept ? (int)pAccept((uint64_t)(unsigned)fd, 0, 0) : -1;
}
static int win_send(int fd, const void *buf, size_t len) {
    return pSend ? pSend((uint64_t)(unsigned)fd, buf, (int)len, 0) : -1;
}
static int win_recv(int fd, void *buf, size_t len) {
    return pRecv ? pRecv((uint64_t)(unsigned)fd, buf, (int)len, 0) : -1;
}
static void win_exit(int code) {
    pExitProcess(code);
    __builtin_unreachable();
}
static void win_sleep_ms(int ms) { pSleep(ms); }
static int win_hostname(char *buf, int len) {
    uint32_t sz = len;
    pGetComputerNameA(buf, &sz);
    return sz;
}
static int win_getpid(void) { return 0; /* TODO */ }
static int win_poll(int fd, int timeout_ms) {
    /* TODO: WSAPoll */
    win_sleep_ms(timeout_ms);
    return 1; /* assume data ready */
}
static int win_exec(const char *cmd, char *outbuf, int outbufsize) {
    /* TODO: CreateProcess + pipe */
    return -1;
}

/* ========================================================================
 * OS DETECTION + VTABLE PATCHING
 * ======================================================================== */

int detect_os(void) {
    /* Try Linux getpid syscall (nr=39). If returns > 0 → Linux.
     * On Windows, `syscall` with Linux ABI either faults or returns nonsense.
     * Safe: getpid always returns a positive PID on Linux. */
    long r;
    __asm__ volatile(
        "mov $39, %%eax\n\t"  /* SYS_GETPID */
        "syscall\n\t"
        : "=a"(r) : : "rcx", "r11", "memory"
    );
    if (r > 0 && r < 0x100000) {
        /* Looks like a valid PID → Linux */
        os_type = 1;
        return 1;
    }
    /* Not Linux → assume Windows */
    os_type = 2;
    return 2;
}

void patch_vtable(void) {
    if (os_type == 2) {
        /* Windows: resolve APIs from PEB, then patch vtable */
        win_resolve_apis();
        vt.write = win_write;    vt.read = win_read;
        vt.open = win_open;      vt.close = win_close;
        vt.seek = win_seek;      vt.filesize = win_filesize;
        vt.rename = win_rename;  vt.unlink = win_unlink;
        vt.mkdir = win_mkdir;    vt.socket = win_socket;
        vt.connect = win_connect; vt.bind = win_bind;
        vt.listen = win_listen;  vt.accept = win_accept;
        vt.send = win_send;      vt.recv = win_recv;
        vt.exec = win_exec;     vt.exit_ = win_exit;
        vt.sleep_ms = win_sleep_ms; vt.hostname = win_hostname;
        vt.getpid = win_getpid;  vt.poll = win_poll;
    } else {
        /* Linux */
        vt.write = lx_write;    vt.read = lx_read;
        vt.open = lx_open;      vt.close = lx_close;
        vt.seek = lx_seek;      vt.filesize = lx_filesize;
        vt.rename = lx_rename;  vt.unlink = lx_unlink;
        vt.mkdir = lx_mkdir;    vt.socket = lx_socket;
        vt.connect = lx_connect; vt.bind = lx_bind;
        vt.listen = lx_listen;  vt.accept = lx_accept;
        vt.send = lx_send;      vt.recv = lx_recv;
        vt.exec = lx_exec;      vt.exit_ = lx_exit;
        vt.sleep_ms = lx_sleep_ms; vt.hostname = lx_hostname;
        vt.getpid = lx_getpid;  vt.poll = lx_poll;
    }
}

/* ========================================================================
 * PORTABLE I/O — all code uses these, routed through vtable
 * ======================================================================== */

ssize_t io_write(int fd, const void *buf, size_t len) { return vt.write(fd, buf, len); }
ssize_t io_read(int fd, void *buf, size_t len) { return vt.read(fd, buf, len); }
int io_open(const char *path, int flags) { return vt.open(path, flags); }
int io_close(int fd) { return vt.close(fd); }
long io_seek(int fd, long off, int whence) { return vt.seek(fd, off, whence); }
long io_filesize(int fd) { return vt.filesize(fd); }
void io_exit(int code) { vt.exit_(code); }
void io_print(int fd, const char *s) {
    size_t n = 0; while (s[n]) n++;
    vt.write(fd, s, n);
}
int net_socket(void) { return vt.socket(); }
int net_connect(int fd, uint32_t ip, uint16_t port) { return vt.connect(fd, ip, port); }
int net_bind(int fd, uint16_t port) { return vt.bind(fd, port); }
int net_listen(int fd, int backlog) { return vt.listen(fd, backlog); }
int net_accept(int fd) { return vt.accept(fd); }
int io_exec(const char *cmd, char *outbuf, int sz) { return vt.exec(cmd, outbuf, sz); }
void io_sleep_ms(int ms) { vt.sleep_ms(ms); }
int io_hostname(char *buf, int len) { return vt.hostname(buf, len); }
