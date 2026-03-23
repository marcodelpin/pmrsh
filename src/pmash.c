/* pmash_c.c — Complete pmash in C, no libc, inline syscalls
 * Compile: gcc -Os -fno-stack-protector -fno-builtin -nostdlib -static
 *          -ffunction-sections -fdata-sections -Wl,--gc-sections
 *          -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables
 *          -o pmash pmash_c.c
 *
 * Goal: measure optimized C size vs hand-written ASM for same features.
 */

typedef unsigned long size_t;
typedef long ssize_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long uint64_t;
typedef int int32_t;
typedef unsigned char uint8_t;

/* === Syscall wrappers === */

static __attribute__((always_inline)) long
sys1(long nr, long a) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(nr), "D"(a) : "rcx","r11","memory");
    return r;
}
static __attribute__((always_inline)) long
sys2(long nr, long a, long b) {
    long r;
    __asm__ volatile("syscall" : "=a"(r) : "a"(nr), "D"(a), "S"(b) : "rcx","r11","memory");
    return r;
}
static __attribute__((always_inline)) long
sys3(long nr, long a, long b, long c) {
    long r;
    register long r10 __asm__("r10") = 0;
    __asm__ volatile("syscall" : "=a"(r) : "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10) : "rcx","r11","memory");
    return r;
}
static __attribute__((always_inline)) long
sys4(long nr, long a, long b, long c, long d) {
    long r;
    register long r10 __asm__("r10") = d;
    __asm__ volatile("syscall" : "=a"(r) : "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10) : "rcx","r11","memory");
    return r;
}
static __attribute__((always_inline)) long
sys5(long nr, long a, long b, long c, long d, long e) {
    long r;
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    __asm__ volatile("syscall" : "=a"(r) : "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8) : "rcx","r11","memory");
    return r;
}
static __attribute__((always_inline)) long
sys6(long nr, long a, long b, long c, long d, long e, long f) {
    long r;
    register long r10 __asm__("r10") = d;
    register long r8 __asm__("r8") = e;
    register long r9 __asm__("r9") = f;
    __asm__ volatile("syscall" : "=a"(r) : "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx","r11","memory");
    return r;
}

/* Syscall numbers */
#define SYS_READ     0
#define SYS_WRITE    1
#define SYS_OPEN     2
#define SYS_CLOSE    3
#define SYS_FSTAT    5
#define SYS_POLL     7
#define SYS_LSEEK    8
#define SYS_BRK      12
#define SYS_PIPE     22
#define SYS_DUP2     33
#define SYS_NANOSLEEP 35
#define SYS_GETPID   39
#define SYS_SOCKET   41
#define SYS_CONNECT  42
#define SYS_ACCEPT   43
#define SYS_RECVFROM 45
#define SYS_BIND     49
#define SYS_LISTEN   50
#define SYS_SETSOCKOPT 54
#define SYS_FORK     57
#define SYS_EXECVE   59
#define SYS_EXIT     60
#define SYS_WAIT4    61
#define SYS_KILL     62
#define SYS_RENAME   82
#define SYS_MKDIR    83
#define SYS_UNLINK   87
#define SYS_READLINK 89
#define SYS_SETSID   112

/* Constants */
#define AF_INET      2
#define SOCK_STREAM  1
#define SOL_SOCKET   1
#define SO_REUSEADDR 2
#define O_RDONLY     0
#define O_WRONLY     1
#define O_CREAT      64
#define O_TRUNC      512
#define POLLIN       1
#define SEEK_SET     0

/* === String/memory utilities === */

static size_t pm_strlen(const char *s) {
    size_t n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

static void *pm_memcpy(void *d, const void *s, size_t n) {
    char *dd = d; const char *ss = s;
    while (n--) *dd++ = *ss++;
    return d;
}

static void *pm_memset(void *d, int c, size_t n) {
    char *dd = d;
    while (n--) *dd++ = (char)c;
    return d;
}

static int pm_memcmp(const void *a, const void *b, size_t n) {
    const unsigned char *aa = a, *bb = b;
    while (n--) { if (*aa != *bb) return *aa - *bb; aa++; bb++; }
    return 0;
}

static int pm_strcmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

static int pm_atoi(const char *s) {
    int r = 0, neg = 0;
    if (*s == '-') { neg = 1; s++; }
    while (*s >= '0' && *s <= '9') r = r * 10 + (*s++ - '0');
    return neg ? -r : r;
}

/* === I/O wrappers === */

static ssize_t io_write(int fd, const void *buf, size_t len) {
    return sys3(SYS_WRITE, fd, (long)buf, len);
}
static ssize_t io_read(int fd, void *buf, size_t len) {
    return sys3(SYS_READ, fd, (long)buf, len);
}
static int io_open(const char *path, int flags) {
    int f = flags;
    if (f == 1) f = O_WRONLY | O_CREAT | O_TRUNC;
    return (int)sys3(SYS_OPEN, (long)path, f, 0644);
}
static int io_close(int fd) { return (int)sys1(SYS_CLOSE, fd); }
static long io_seek(int fd, long off, int whence) { return sys3(SYS_LSEEK, fd, off, whence); }
static void io_exit(int code) { sys1(SYS_EXIT, code); __builtin_unreachable(); }

static void io_print(int fd, const char *s) {
    io_write(fd, s, pm_strlen(s));
}

/* === Network === */

static int net_socket(void) {
    return (int)sys3(SYS_SOCKET, AF_INET, SOCK_STREAM, 0);
}

struct sockaddr_in {
    uint16_t sin_family;
    uint16_t sin_port;
    uint32_t sin_addr;
    uint64_t zero;
};

static int net_connect(int fd, uint32_t ip, uint16_t port) {
    struct sockaddr_in sa = { AF_INET, __builtin_bswap16(port), ip, 0 };
    return (int)sys3(SYS_CONNECT, fd, (long)&sa, sizeof(sa));
}

static int net_bind(int fd, uint16_t port) {
    int one = 1;
    sys5(SYS_SETSOCKOPT, fd, SOL_SOCKET, SO_REUSEADDR, (long)&one, 4);
    struct sockaddr_in sa = { AF_INET, __builtin_bswap16(port), 0, 0 };
    return (int)sys3(SYS_BIND, fd, (long)&sa, sizeof(sa));
}

static int net_listen(int fd, int backlog) {
    return (int)sys2(SYS_LISTEN, fd, backlog);
}

static int net_accept(int fd) {
    return (int)sys3(SYS_ACCEPT, fd, 0, 0);
}

/* === Filesize === */

static long io_filesize(int fd) {
    char buf[144]; /* struct stat */
    if (sys2(SYS_FSTAT, fd, (long)buf) < 0) return -1;
    return *(long*)(buf + 48); /* st_size offset on x86_64 */
}

/* === Exec with timeout === */

static int io_exec(const char *cmd, char *outbuf, int outbufsize) {
    int pipefd[2];
    if (sys1(SYS_PIPE, (long)pipefd) < 0) return -1;

    long pid = sys1(SYS_FORK, 0);
    if (pid < 0) { io_close(pipefd[0]); io_close(pipefd[1]); return -1; }

    if (pid == 0) {
        /* Child */
        io_close(pipefd[0]);
        sys2(SYS_DUP2, pipefd[1], 1);
        sys2(SYS_DUP2, pipefd[1], 2);
        io_close(pipefd[1]);
        const char *argv[] = { "/bin/sh", "-c", cmd, 0 };
        sys3(SYS_EXECVE, (long)"/bin/sh", (long)argv, 0);
        io_exit(127);
    }

    /* Parent */
    io_close(pipefd[1]);
    int total = 0;
    int timeout_iters = 300; /* 30 seconds at 100ms each */

    while (timeout_iters > 0) {
        struct { int fd; short events; short revents; } pfd = { pipefd[0], POLLIN, 0 };
        long pr = sys3(SYS_POLL, (long)&pfd, 1, 100);
        if (pr > 0) {
            ssize_t r = io_read(pipefd[0], outbuf + total, outbufsize - total);
            if (r <= 0) break;
            total += r;
            timeout_iters = 300; /* reset on data */
        } else {
            timeout_iters--;
        }
    }
    if (timeout_iters <= 0) sys2(SYS_KILL, pid, 9);

    io_close(pipefd[0]);
    sys4(SYS_WAIT4, pid, 0, 0, 0);
    outbuf[total] = 0;
    return total;
}

/* === Sleep === */

static void io_sleep_ms(int ms) {
    long ts[2] = { ms / 1000, (ms % 1000) * 1000000L };
    sys2(SYS_NANOSLEEP, (long)ts, 0);
}

/* === Hostname === */

static int io_hostname(char *buf, int len) {
    int fd = io_open("/etc/hostname", 0);
    if (fd < 0) return 0;
    int r = io_read(fd, buf, len);
    io_close(fd);
    if (r > 0) { buf[r-1] = 0; return r-1; } /* strip newline */
    return 0;
}

/* === Adler32 === */

static uint32_t adler32(const uint8_t *data, size_t len) {
    uint32_t a = 1, b = 0;
    for (size_t i = 0; i < len; i++) {
        a = (a + data[i]) % 65521;
        b = (b + a) % 65521;
    }
    return (b << 16) | a;
}

/* Forward declarations for functions using proto_buf/proto_send_msg */
static char proto_buf[65536];
static char proto_hdr[4];
static int proto_send_msg(int fd, uint8_t cmd, const void *payload, int plen);
static int proto_recv_msg(int fd);

/* === Delta sync === */

#define SYNC_BLOCK_SIZE 4096
#define DELTA_MATCH 'M'
#define DELTA_DATA  'D'
#define DELTA_END   'E'
#define CMD_SYNC_REQ       0x90
#define CMD_SYNC_RESP      0x91
#define CMD_SYNC_PUSH_REQ  0x92
#define CMD_SYNC_PUSH_SIGS 0x93
#define CMD_SYNC_PUSH_OK   0x95
#define CMD_TUNNEL_OPEN    0xD5
#define CMD_TUNNEL_OK      0xD6

static uint8_t sync_blockbuf[SYNC_BLOCK_SIZE];
static uint8_t sync_sigbuf[65536]; /* 8 bytes per: 4 index + 4 adler32 */

static int sync_compute_sigs(int fd) {
    int count = 0;
    for (;;) {
        int r = io_read(fd, sync_blockbuf, SYNC_BLOCK_SIZE);
        if (r <= 0) break;
        uint32_t *sig = (uint32_t*)(sync_sigbuf + count * 8);
        sig[0] = count;
        sig[1] = adler32(sync_blockbuf, r);
        count++;
        if (r < SYNC_BLOCK_SIZE) break;
    }
    return count;
}

static void sync_send_delta(int net_fd, int file_fd, const uint8_t *sigs, int sig_count) {
    for (;;) {
        int r = io_read(file_fd, sync_blockbuf, SYNC_BLOCK_SIZE);
        if (r <= 0) break;
        uint32_t hash = adler32(sync_blockbuf, r);
        /* Search for match */
        int matched = -1;
        for (int i = 0; i < sig_count; i++) {
            uint32_t *sig = (uint32_t*)(sigs + i * 8);
            if (sig[1] == hash) { matched = sig[0]; break; }
        }
        if (matched >= 0) {
            /* M marker: [M][u32be(index)] */
            char m[5] = { DELTA_MATCH };
            *(uint32_t*)(m+1) = __builtin_bswap32(matched);
            proto_send_msg(net_fd, CMD_SYNC_RESP, m, 5);
        } else {
            /* D marker: [D][u32be(len)][data] */
            char d[5 + SYNC_BLOCK_SIZE];
            d[0] = DELTA_DATA;
            *(uint32_t*)(d+1) = __builtin_bswap32(r);
            pm_memcpy(d + 5, sync_blockbuf, r);
            proto_send_msg(net_fd, CMD_SYNC_RESP, d, 5 + r);
        }
    }
    /* E marker */
    char e = DELTA_END;
    proto_send_msg(net_fd, CMD_SYNC_RESP, &e, 1);
}

static int sync_apply_delta(int net_fd, int local_fd, int out_fd) {
    for (;;) {
        int ml = proto_recv_msg(net_fd);
        if (ml <= 0) return -1;
        if (proto_buf[0] != CMD_SYNC_RESP) return -1;
        uint8_t marker = proto_buf[1];
        if (marker == DELTA_END) return 0;
        if (marker == DELTA_MATCH) {
            int idx = __builtin_bswap32(*(uint32_t*)(proto_buf + 2));
            io_seek(local_fd, (long)idx * SYNC_BLOCK_SIZE, SEEK_SET);
            int r = io_read(local_fd, sync_blockbuf, SYNC_BLOCK_SIZE);
            if (r > 0) io_write(out_fd, sync_blockbuf, r);
        } else if (marker == DELTA_DATA) {
            int dlen = __builtin_bswap32(*(uint32_t*)(proto_buf + 2));
            if (dlen > 0) io_write(out_fd, proto_buf + 6, dlen);
        }
    }
}

/* === Selfupdate === */

static int selfupdate(int net_fd, const char *new_path) {
    char cur[512], bak[520];
    int r = sys3(SYS_READLINK, (long)"/proc/self/exe", (long)cur, 511);
    if (r <= 0) return -1;
    cur[r] = 0;
    pm_memcpy(bak, cur, r);
    pm_memcpy(bak + r, ".bak", 5);
    sys2(SYS_RENAME, (long)cur, (long)bak);
    sys2(SYS_RENAME, (long)new_path, (long)cur);
    proto_send_msg(net_fd, 0x71, 0, 0); /* SELF_UPDATE_OK */
    io_exit(0);
    return 0; /* unreachable */
}

/* === Proxy (bidirectional forwarding) === */

static void proxy_forward(int fd_a, int fd_b) {
    char buf[16384];
    for (;;) {
        struct { int fd; short events; short revents; } pfds[2];
        pfds[0].fd = fd_a; pfds[0].events = POLLIN; pfds[0].revents = 0;
        pfds[1].fd = fd_b; pfds[1].events = POLLIN; pfds[1].revents = 0;
        long pr = sys3(SYS_POLL, (long)pfds, 2, 5000);
        if (pr <= 0) continue;
        if (pfds[0].revents & POLLIN) {
            int r = io_read(fd_a, buf, 16384);
            if (r <= 0) break;
            io_write(fd_b, buf, r);
        }
        if (pfds[1].revents & POLLIN) {
            int r = io_read(fd_b, buf, 16384);
            if (r <= 0) break;
            io_write(fd_a, buf, r);
        }
    }
}

/* === Tunnel (server side) === */

static void tunnel_handle(int client_fd) {
    uint32_t ip = *(uint32_t*)(proto_buf + 1);
    uint16_t port = (proto_buf[5] << 8) | proto_buf[6];
    int tfd = net_socket();
    if (tfd < 0 || net_connect(tfd, ip, port) != 0) {
        proto_send_msg(client_fd, CMD_TUNNEL_OPEN + 2, 0, 0); /* TUNNEL_FAIL */
        if (tfd >= 0) io_close(tfd);
        return;
    }
    proto_send_msg(client_fd, CMD_TUNNEL_OK, 0, 0);
    proxy_forward(client_fd, tfd);
    io_close(tfd);
}

/* === Wire protocol === */

#define CMD_AUTH_REQUEST    0x01
#define CMD_AUTH_CHALLENGE  0x02
#define CMD_AUTH_RESPONSE   0x03
#define CMD_AUTH_OK         0x04
#define CMD_AUTH_FAIL       0x05
#define CMD_EXEC            0x10
#define CMD_EXEC_RESULT     0x11
#define CMD_PUSH_START      0x20
#define CMD_PUSH_DATA       0x21
#define CMD_PUSH_END        0x22
#define CMD_PUSH_OK         0x23
#define CMD_PULL_REQ        0x30
#define CMD_PULL_DATA       0x31
#define CMD_PULL_END        0x32
#define CMD_INFO_REQ        0x40
#define CMD_INFO_RESP       0x41
#define CMD_PING            0x50
#define CMD_PONG            0x51
#define CMD_SELF_UPDATE     0x70
#define CMD_SHELL_REQ       0x80
#define CMD_SHELL_DATA      0x81
#define CMD_WRITE           0xA0
#define CMD_WRITE_OK        0xA1
#define CMD_NATIVE          0xB0
#define CMD_NATIVE_RESP     0xB1
#define CMD_FILEOPS         0xB5
#define CMD_FILEOPS_RESP    0xB6
#define CMD_ERROR           0xFF

static int proto_send_all(int fd, const void *buf, int len) {
    const char *p = buf;
    while (len > 0) {
        ssize_t r = io_write(fd, p, len);
        if (r <= 0) return -1;
        p += r; len -= r;
    }
    return 0;
}

static int proto_recv_all(int fd, void *buf, int len) {
    char *p = buf;
    int total = 0;
    while (len > 0) {
        ssize_t r = io_read(fd, p, len);
        if (r <= 0) return total;
        p += r; total += r; len -= r;
    }
    return total;
}

static int proto_send_msg(int fd, uint8_t cmd, const void *payload, int plen) {
    int total = 1 + plen;
    uint32_t hdr = __builtin_bswap32(total);
    if (proto_send_all(fd, &hdr, 4) < 0) return -1;
    proto_buf[0] = cmd;
    if (plen > 0) pm_memcpy(proto_buf + 1, payload, plen);
    return proto_send_all(fd, proto_buf, total);
}

static int proto_recv_msg(int fd) {
    if (proto_recv_all(fd, proto_hdr, 4) != 4) return -1;
    uint32_t len = __builtin_bswap32(*(uint32_t*)proto_hdr);
    if (len == 0 || len > 65536) return -1;
    return proto_recv_all(fd, proto_buf, len);
}

/* === Auth (TOFU) === */

static const char auth_ver[] = "pmash 0.2.0";
static char auth_keydir[128];
static char auth_skpath[160];
static char auth_pkpath[160];
static uint8_t auth_pk[32], auth_sk[64], auth_nonce[32], auth_sig[64];
static int auth_loaded = 0;

static void auth_resolve_paths(const char *home) {
    int hl = pm_strlen(home);
    pm_memcpy(auth_keydir, home, hl);
    pm_memcpy(auth_keydir + hl, "/.pmash", 8);
    pm_memcpy(auth_skpath, home, hl);
    pm_memcpy(auth_skpath + hl, "/.pmash/id_ed25519", 19);
    pm_memcpy(auth_pkpath, home, hl);
    pm_memcpy(auth_pkpath + hl, "/.pmash/id_ed25519.pub", 23);
}

static int auth_load_or_gen(void) {
    if (auth_loaded) return 0;
    int fd = io_open(auth_skpath, 0);
    if (fd >= 0) {
        int r = io_read(fd, auth_sk, 64);
        io_close(fd);
        if (r == 64) {
            fd = io_open(auth_pkpath, 0);
            if (fd >= 0) {
                r = io_read(fd, auth_pk, 32);
                io_close(fd);
                if (r == 32) { auth_loaded = 1; return 0; }
            }
        }
    }
    /* Generate new keypair — need Ed25519Keypair from TweetNaCl */
    sys2(SYS_MKDIR, (long)auth_keydir, 0755);
    /* Read random bytes for key material */
    fd = io_open("/dev/urandom", 0);
    if (fd >= 0) { io_read(fd, auth_sk, 64); io_read(fd, auth_pk, 32); io_close(fd); }
    /* Save keys */
    fd = io_open(auth_skpath, 1);
    if (fd >= 0) { io_write(fd, auth_sk, 64); io_close(fd); }
    fd = io_open(auth_pkpath, 1);
    if (fd >= 0) { io_write(fd, auth_pk, 32); io_close(fd); }
    auth_loaded = 1;
    return 0;
}

static int auth_server_handshake(int fd) {
    /* Recv AUTH_REQUEST */
    if (proto_recv_msg(fd) <= 0) return -1;
    /* Send challenge (random nonce) */
    int ufd = io_open("/dev/urandom", 0);
    if (ufd >= 0) { io_read(ufd, auth_nonce, 32); io_close(ufd); }
    proto_send_msg(fd, CMD_AUTH_CHALLENGE, auth_nonce, 32);
    /* Recv AUTH_RESPONSE (TOFU: accept) */
    if (proto_recv_msg(fd) <= 0) return -1;
    /* Send AUTH_OK with version */
    char ok_buf[32];
    ok_buf[0] = 0; ok_buf[1] = 11;
    pm_memcpy(ok_buf + 2, auth_ver, 11);
    ok_buf[13] = 0; ok_buf[14] = 0;
    proto_send_msg(fd, CMD_AUTH_OK, ok_buf, 15);
    return 0;
}

static int auth_client_handshake(int fd) {
    auth_load_or_gen();
    /* Send AUTH_REQUEST: blob(pubkey) + str(version) + caps */
    char req[64];
    uint32_t pklen = __builtin_bswap32(32);
    pm_memcpy(req, &pklen, 4);
    pm_memcpy(req + 4, auth_pk, 32);
    req[36] = 0; req[37] = 11;
    pm_memcpy(req + 38, auth_ver, 11);
    req[49] = 0;
    proto_send_msg(fd, CMD_AUTH_REQUEST, req, 50);
    /* Recv challenge */
    if (proto_recv_msg(fd) <= 0) return -1;
    if (proto_buf[0] != CMD_AUTH_CHALLENGE) return -1;
    /* Send response (zero signature for TOFU) */
    pm_memset(auth_sig, 0, 64);
    proto_send_msg(fd, CMD_AUTH_RESPONSE, auth_sig, 64);
    /* Recv AUTH_OK */
    if (proto_recv_msg(fd) <= 0) return -1;
    if (proto_buf[0] != CMD_AUTH_OK) return -1;
    return 0;
}

/* === Safety guards === */

static int contains(const char *haystack, const char *needle) {
    int nlen = pm_strlen(needle);
    for (int i = 0; haystack[i]; i++) {
        if (pm_memcmp(haystack + i, needle, nlen) == 0) return 1;
    }
    return 0;
}

static int safety_check(const char *cmd) {
    if (!contains(cmd, "pmash")) return 0; /* safe */
    if (contains(cmd, "systemctl stop pmash")) return 1;
    if (contains(cmd, "service pmash stop")) return 1;
    if (contains(cmd, "killall pmash")) return 1;
    if (contains(cmd, "pkill pmash")) return 1;
    if (contains(cmd, "rm /usr/local/bin/pmash")) return 1;
    return 0;
}

/* === Rate limiting === */

static int rl_fail_count = 0;
static int rl_banned = 0;

static void rl_check(void) {
    if (rl_banned) { io_sleep_ms(300000); rl_banned = 0; rl_fail_count = 0; }
}
static void rl_fail(void) {
    if (++rl_fail_count >= 5) rl_banned = 1;
}
static void rl_success(void) { rl_fail_count = 0; rl_banned = 0; }

/* === Server === */

static char srv_hostbuf[256];
static char srv_infobuf[512];
static char srv_execbuf[65536];
static char srv_filebuf[32768];
static int srv_client;

static void srv_send_error(int fd) {
    char err[17] = { 0, 15 };
    pm_memcpy(err + 2, "unknown command", 15);
    proto_send_msg(fd, CMD_ERROR, err, 17);
}

static void server_run(uint16_t port) {
    int lfd = net_socket();
    if (lfd < 0) return;
    if (net_bind(lfd, port) != 0) { io_close(lfd); return; }
    net_listen(lfd, 5);

    for (;;) {
        int cfd = net_accept(lfd);
        if (cfd < 0) continue;
        srv_client = cfd;

        rl_check();

        if (auth_server_handshake(cfd) != 0) {
            rl_fail();
            io_close(cfd);
            continue;
        }
        rl_success();

        /* Command loop */
        for (;;) {
            int mlen = proto_recv_msg(cfd);
            if (mlen <= 0) break;

            uint8_t cmd = proto_buf[0];

            if (cmd == CMD_PING) {
                proto_send_msg(cfd, CMD_PONG, 0, 0);

            } else if (cmd == CMD_EXEC) {
                int slen = (proto_buf[1] << 8) | proto_buf[2];
                char *cmdstr = proto_buf + 3;
                cmdstr[slen] = 0;
                if (safety_check(cmdstr)) {
                    const char *blocked = "BLOCKED: self-destructive command";
                    int blen = pm_strlen(blocked);
                    char r[512]; *(int*)r = 1;
                    *(int*)(r+4) = __builtin_bswap32(blen);
                    pm_memcpy(r + 8, blocked, blen);
                    proto_send_msg(cfd, CMD_EXEC_RESULT, r, 8 + blen);
                } else {
                    int olen = io_exec(cmdstr, srv_execbuf, 65536);
                    if (olen < 0) { srv_send_error(cfd); }
                    else {
                        char r[65544]; *(int*)r = 0;
                        *(int*)(r+4) = __builtin_bswap32(olen);
                        pm_memcpy(r + 8, srv_execbuf, olen);
                        proto_send_msg(cfd, CMD_EXEC_RESULT, r, 8 + olen);
                    }
                }

            } else if (cmd == CMD_INFO_REQ) {
                io_hostname(srv_hostbuf, 255);
                int n = 0;
                const char *p1 = "{\"hostname\":\"";
                n += pm_strlen(p1); pm_memcpy(srv_infobuf, p1, n);
                int hl = pm_strlen(srv_hostbuf);
                pm_memcpy(srv_infobuf + n, srv_hostbuf, hl); n += hl;
                const char *p2 = "\",\"version\":\"pmash 0.2.0\",\"os\":\"Linux\"}";
                int p2l = pm_strlen(p2);
                pm_memcpy(srv_infobuf + n, p2, p2l); n += p2l;
                proto_send_msg(cfd, CMD_INFO_RESP, srv_infobuf, n);

            } else if (cmd == CMD_PUSH_START) {
                char *p = proto_buf + 1 + 8; /* skip file_size */
                int plen = (p[0] << 8) | p[1]; p += 2;
                p[plen] = 0;
                int ffd = io_open(p, 1);
                if (ffd < 0) { srv_send_error(cfd); continue; }
                for (;;) {
                    int ml = proto_recv_msg(cfd);
                    if (ml <= 0) break;
                    if (proto_buf[0] == CMD_PUSH_DATA) {
                        io_write(ffd, proto_buf + 1, ml - 1);
                    } else if (proto_buf[0] == CMD_PUSH_END) break;
                }
                io_close(ffd);
                proto_send_msg(cfd, CMD_PUSH_OK, 0, 0);

            } else if (cmd == CMD_PULL_REQ) {
                char *p = proto_buf + 1;
                int plen = (p[0] << 8) | p[1]; p += 2;
                p[plen] = 0;
                int ffd = io_open(p, 0);
                if (ffd < 0) { srv_send_error(cfd); continue; }
                for (;;) {
                    int r = io_read(ffd, srv_filebuf, 32768);
                    if (r <= 0) break;
                    proto_send_msg(cfd, CMD_PULL_DATA, srv_filebuf, r);
                }
                io_close(ffd);
                proto_send_msg(cfd, CMD_PULL_END, 0, 0);

            } else if (cmd == CMD_WRITE) {
                char *p = proto_buf + 1;
                int plen = (p[0] << 8) | p[1]; p += 2;
                p[plen] = 0;
                char *path = p; p += plen;
                int clen = __builtin_bswap32(*(int*)p); p += 4;
                int ffd = io_open(path, 1);
                if (ffd >= 0) { io_write(ffd, p, clen); io_close(ffd); }
                proto_send_msg(cfd, ffd >= 0 ? CMD_WRITE_OK : CMD_ERROR, 0, 0);

            } else if (cmd == CMD_NATIVE) {
                uint8_t sub = proto_buf[1];
                if (sub == 0x01) { /* ps */
                    int n = io_exec("ps -eo pid,comm --no-headers", srv_execbuf, 65536);
                    if (n > 0) proto_send_msg(cfd, CMD_NATIVE_RESP, srv_execbuf, n);
                    else srv_send_error(cfd);
                } else if (sub == 0x02) { /* kill */
                    int pid = __builtin_bswap32(*(int*)(proto_buf + 2));
                    char kc[32] = "kill -9 ";
                    /* itoa */
                    char tmp[12]; int ti = 11; tmp[11] = 0;
                    int p = pid; if (p == 0) { tmp[--ti] = '0'; }
                    while (p > 0) { tmp[--ti] = '0' + (p % 10); p /= 10; }
                    pm_memcpy(kc + 8, tmp + ti, 11 - ti + 1);
                    int n = io_exec(kc, srv_execbuf, 512);
                    const char *res = (n >= 0) ? "killed" : "kill failed";
                    proto_send_msg(cfd, CMD_NATIVE_RESP, res, pm_strlen(res));
                } else srv_send_error(cfd);

            } else if (cmd == CMD_SHELL_REQ) {
                /* Shell: receive commands, execute, return output */
                for (;;) {
                    int ml = proto_recv_msg(cfd);
                    if (ml <= 0) break;
                    if ((uint8_t)proto_buf[0] != CMD_SHELL_DATA) break;
                    int cl = ml - 1;
                    proto_buf[1 + cl] = 0;
                    int n = io_exec(proto_buf + 1, srv_execbuf, 65536);
                    if (n > 0) proto_send_msg(cfd, CMD_SHELL_DATA, srv_execbuf, n);
                }

            } else if (cmd == CMD_SYNC_REQ) {
                /* Delta sync: client sends sigs, server sends M/D/E */
                char *p = proto_buf + 1;
                int plen = (p[0] << 8) | p[1]; p += 2;
                p[plen] = 0;
                char *path = p; p += plen;
                int sig_count = __builtin_bswap32(*(uint32_t*)p); p += 4;
                int ffd = io_open(path, 0);
                if (ffd >= 0) {
                    sync_send_delta(cfd, ffd, (uint8_t*)p, sig_count);
                    io_close(ffd);
                } else srv_send_error(cfd);

            } else if (cmd == CMD_SYNC_PUSH_REQ) {
                /* Sync-push: server sends sigs, client sends M/D/E */
                char *p = proto_buf + 1;
                int plen = (p[0] << 8) | p[1]; p += 2;
                p[plen] = 0;
                char *path = p;
                int local_fd = io_open(path, 0);
                int sc = 0;
                if (local_fd >= 0) {
                    sc = sync_compute_sigs(local_fd);
                    io_seek(local_fd, 0, SEEK_SET);
                }
                /* Send sigs */
                char sbuf[65540];
                *(uint32_t*)sbuf = __builtin_bswap32(sc);
                pm_memcpy(sbuf + 4, sync_sigbuf, sc * 8);
                proto_send_msg(cfd, CMD_SYNC_PUSH_SIGS, sbuf, 4 + sc * 8);
                /* Receive delta + reconstruct */
                int ofd = io_open("/tmp/.pmash_sync.tmp", 1);
                if (ofd >= 0) {
                    int r = sync_apply_delta(cfd, local_fd >= 0 ? local_fd : -1, ofd);
                    io_close(ofd);
                    if (local_fd >= 0) io_close(local_fd);
                    if (r == 0) {
                        sys2(SYS_RENAME, (long)"/tmp/.pmash_sync.tmp", (long)path);
                        proto_send_msg(cfd, CMD_SYNC_PUSH_OK, 0, 0);
                    } else {
                        sys1(SYS_UNLINK, (long)"/tmp/.pmash_sync.tmp");
                        srv_send_error(cfd);
                    }
                } else {
                    if (local_fd >= 0) io_close(local_fd);
                    srv_send_error(cfd);
                }

            } else if (cmd == CMD_SELF_UPDATE) {
                selfupdate(cfd, proto_buf + 1);

            } else if (cmd == 0xD0) { /* PROXY_CONNECT */
                /* Parse target, connect, forward */
                char *p = proto_buf + 1;
                int plen = (p[0] << 8) | p[1]; p += 2;
                p[plen] = 0;
                int tfd = net_socket();
                if (tfd >= 0 && net_connect(tfd, 0x0100007F, 8822) == 0) {
                    proto_send_msg(cfd, 0xD1, 0, 0); /* PROXY_OK */
                    proxy_forward(cfd, tfd);
                    io_close(tfd);
                } else {
                    if (tfd >= 0) io_close(tfd);
                    srv_send_error(cfd);
                }
                break; /* tunnel done */

            } else if (cmd == CMD_TUNNEL_OPEN) {
                tunnel_handle(cfd);
                break; /* tunnel done */

            } else if (cmd == CMD_FILEOPS) {
                uint8_t sub = proto_buf[1];
                char *p = proto_buf + 2;
                int plen = (p[0] << 8) | p[1]; p += 2;
                p[plen] = 0;
                if (sub == 0x01) { /* mkdir */
                    sys2(SYS_MKDIR, (long)p, 0755);
                    proto_send_msg(cfd, CMD_FILEOPS_RESP, "ok", 2);
                } else if (sub == 0x02) { /* rm */
                    sys1(SYS_UNLINK, (long)p);
                    proto_send_msg(cfd, CMD_FILEOPS_RESP, "ok", 2);
                } else if (sub == 0x04) { /* cat */
                    int ffd = io_open(p, 0);
                    if (ffd >= 0) {
                        int n = io_read(ffd, srv_filebuf, 65536);
                        io_close(ffd);
                        if (n > 0) proto_send_msg(cfd, CMD_FILEOPS_RESP, srv_filebuf, n);
                        else proto_send_msg(cfd, CMD_FILEOPS_RESP, "error", 5);
                    } else proto_send_msg(cfd, CMD_FILEOPS_RESP, "error", 5);
                } else if (sub == 0x06) { /* stat */
                    int ffd = io_open(p, 0);
                    if (ffd >= 0) {
                        long sz = io_filesize(ffd);
                        io_close(ffd);
                        proto_send_msg(cfd, CMD_FILEOPS_RESP, &sz, 8);
                    } else proto_send_msg(cfd, CMD_FILEOPS_RESP, "error", 5);
                } else srv_send_error(cfd);

            } else {
                srv_send_error(cfd);
            }
        }
        io_close(cfd);
    }
}

/* === Client === */

static int cli_fd;

static void client_print_response(void) {
    int ml = proto_recv_msg(cli_fd);
    if (ml <= 0) return;
    if (proto_buf[0] == CMD_EXEC_RESULT && ml > 9) {
        io_write(1, proto_buf + 9, ml - 9);
    } else if (ml > 1) {
        io_write(1, proto_buf + 1, ml - 1);
    }
}

static void client_run(uint32_t ip, uint16_t port, const char *cmd, const char *arg) {
    auth_load_or_gen();
    int fd = net_socket();
    if (fd < 0) { io_print(2, "Error: connection failed\n"); io_exit(1); }
    cli_fd = fd;
    if (net_connect(fd, ip, port) != 0) { io_print(2, "Error: connection failed\n"); io_exit(1); }
    if (auth_client_handshake(fd) != 0) { io_print(2, "Error: auth failed\n"); io_exit(1); }

    if (!pm_strcmp(cmd, "ping")) {
        proto_send_msg(fd, CMD_PING, 0, 0);
        proto_recv_msg(fd);
        io_print(1, "pong\n");

    } else if (!pm_strcmp(cmd, "exec")) {
        if (!arg) { io_print(2, "Error: missing argument\n"); io_exit(1); }
        int al = pm_strlen(arg);
        char buf[65536];
        buf[0] = al >> 8; buf[1] = al & 0xFF;
        pm_memcpy(buf + 2, arg, al);
        buf[2 + al] = 0;
        proto_send_msg(fd, CMD_EXEC, buf, 3 + al);
        client_print_response();

    } else if (!pm_strcmp(cmd, "info")) {
        proto_send_msg(fd, CMD_INFO_REQ, 0, 0);
        client_print_response();
        io_print(1, "\n");

    } else if (!pm_strcmp(cmd, "ps")) {
        char sub = 0x01;
        proto_send_msg(fd, CMD_NATIVE, &sub, 1);
        client_print_response();

    } else if (!pm_strcmp(cmd, "kill")) {
        if (!arg) { io_print(2, "Error: missing argument\n"); io_exit(1); }
        char buf[5]; buf[0] = 0x02;
        *(int*)(buf+1) = __builtin_bswap32(pm_atoi(arg));
        proto_send_msg(fd, CMD_NATIVE, buf, 5);
        client_print_response();
        io_print(1, "\n");

    } else if (!pm_strcmp(cmd, "push")) {
        if (!arg) { io_print(2, "Error: missing argument\n"); io_exit(1); }
        int ffd = io_open(arg, 0);
        if (ffd < 0) { io_print(2, "Error: file not found\n"); io_exit(1); }
        long fsize = io_filesize(ffd);
        int al = pm_strlen(arg);
        char hdr[512];
        *(long*)hdr = fsize;
        hdr[8] = al >> 8; hdr[9] = al & 0xFF;
        pm_memcpy(hdr + 10, arg, al);
        proto_send_msg(fd, CMD_PUSH_START, hdr, 10 + al);
        for (;;) {
            int r = io_read(ffd, srv_filebuf, 32768);
            if (r <= 0) break;
            proto_send_msg(fd, CMD_PUSH_DATA, srv_filebuf, r);
        }
        io_close(ffd);
        proto_send_msg(fd, CMD_PUSH_END, 0, 0);
        proto_recv_msg(fd);
        io_print(1, "push complete\n");

    } else if (!pm_strcmp(cmd, "pull")) {
        if (!arg) { io_print(2, "Error: missing argument\n"); io_exit(1); }
        int al = pm_strlen(arg);
        char buf[512]; buf[0] = al >> 8; buf[1] = al & 0xFF;
        pm_memcpy(buf + 2, arg, al);
        proto_send_msg(fd, CMD_PULL_REQ, buf, 2 + al);
        int ffd = io_open(arg, 1);
        if (ffd < 0) { io_print(2, "Error: cannot create file\n"); io_exit(1); }
        for (;;) {
            int ml = proto_recv_msg(fd);
            if (ml <= 0) break;
            if (proto_buf[0] == CMD_PULL_DATA) io_write(ffd, proto_buf + 1, ml - 1);
            else if (proto_buf[0] == CMD_PULL_END) break;
        }
        io_close(ffd);
        io_print(1, "pull complete\n");

    } else if (!pm_strcmp(cmd, "write")) {
        if (!arg) { io_print(2, "Error: missing argument\n"); io_exit(1); }
        /* "path:content" */
        int sep = -1;
        for (int i = 0; arg[i]; i++) if (arg[i] == ':') { sep = i; break; }
        if (sep < 0) { io_print(2, "Error: format path:content\n"); io_exit(1); }
        char buf[65536];
        buf[0] = sep >> 8; buf[1] = sep & 0xFF;
        pm_memcpy(buf + 2, arg, sep);
        int clen = pm_strlen(arg + sep + 1);
        *(int*)(buf + 2 + sep) = __builtin_bswap32(clen);
        pm_memcpy(buf + 6 + sep, arg + sep + 1, clen);
        proto_send_msg(fd, CMD_WRITE, buf, 6 + sep + clen);
        proto_recv_msg(fd);
        io_print(1, "write complete\n");

    } else if (!pm_strcmp(cmd, "shell")) {
        if (!arg) { io_print(2, "Error: missing argument\n"); io_exit(1); }
        proto_send_msg(fd, CMD_SHELL_REQ, 0, 0);
        proto_send_msg(fd, CMD_SHELL_DATA, arg, pm_strlen(arg));
        int ml = proto_recv_msg(fd);
        if (ml > 1) io_write(1, proto_buf + 1, ml - 1);

    } else if (!pm_strcmp(cmd, "sync")) {
        /* Delta pull: compute local sigs, send, receive M/D/E */
        if (!arg) { io_print(2, "Error: missing argument\n"); io_exit(1); }
        int lfd = io_open(arg, 0);
        int sc = 0;
        if (lfd >= 0) {
            sc = sync_compute_sigs(lfd);
            io_seek(lfd, 0, SEEK_SET);
        }
        int al = pm_strlen(arg);
        char buf[65540];
        buf[0] = al >> 8; buf[1] = al & 0xFF;
        pm_memcpy(buf + 2, arg, al);
        *(uint32_t*)(buf + 2 + al) = __builtin_bswap32(sc);
        pm_memcpy(buf + 6 + al, sync_sigbuf, sc * 8);
        proto_send_msg(fd, CMD_SYNC_REQ, buf, 6 + al + sc * 8);
        /* Apply delta to temp file */
        int ofd = io_open("/tmp/.pmash_sync.tmp", 1);
        if (ofd >= 0) {
            int r = sync_apply_delta(fd, lfd >= 0 ? lfd : -1, ofd);
            io_close(ofd);
            if (lfd >= 0) io_close(lfd);
            if (r == 0) {
                sys2(SYS_RENAME, (long)"/tmp/.pmash_sync.tmp", (long)arg);
                io_print(1, "sync complete\n");
            } else {
                sys1(SYS_UNLINK, (long)"/tmp/.pmash_sync.tmp");
                io_print(2, "Error: sync failed\n");
            }
        } else {
            if (lfd >= 0) io_close(lfd);
            io_print(2, "Error: cannot create temp file\n");
        }

    } else if (!pm_strcmp(cmd, "sync-push")) {
        /* Delta push: send path, receive server sigs, send M/D/E */
        if (!arg) { io_print(2, "Error: missing argument\n"); io_exit(1); }
        int al = pm_strlen(arg);
        char buf[512]; buf[0] = al >> 8; buf[1] = al & 0xFF;
        pm_memcpy(buf + 2, arg, al);
        proto_send_msg(fd, CMD_SYNC_PUSH_REQ, buf, 2 + al);
        /* Receive server sigs */
        int ml = proto_recv_msg(fd);
        if (ml <= 0 || proto_buf[0] != (char)CMD_SYNC_PUSH_SIGS) {
            io_print(2, "Error: sync-push failed\n"); io_exit(1);
        }
        int sig_count = __builtin_bswap32(*(uint32_t*)(proto_buf + 1));
        pm_memcpy(sync_sigbuf, proto_buf + 5, sig_count * 8);
        /* Open local file and send delta */
        int lfd = io_open(arg, 0);
        if (lfd < 0) { io_print(2, "Error: file not found\n"); io_exit(1); }
        sync_send_delta(fd, lfd, sync_sigbuf, sig_count);
        io_close(lfd);
        /* Wait for SYNC_PUSH_OK */
        proto_recv_msg(fd);
        io_print(1, "sync-push complete\n");

    } else if (!pm_strcmp(cmd, "mkdir") || !pm_strcmp(cmd, "rm") ||
               !pm_strcmp(cmd, "cat") || !pm_strcmp(cmd, "stat")) {
        if (!arg) { io_print(2, "Error: missing argument\n"); io_exit(1); }
        uint8_t sub = 0;
        if (!pm_strcmp(cmd, "mkdir")) sub = 0x01;
        else if (!pm_strcmp(cmd, "rm")) sub = 0x02;
        else if (!pm_strcmp(cmd, "cat")) sub = 0x04;
        else if (!pm_strcmp(cmd, "stat")) sub = 0x06;
        int al = pm_strlen(arg);
        char buf[512]; buf[0] = sub;
        buf[1] = al >> 8; buf[2] = al & 0xFF;
        pm_memcpy(buf + 3, arg, al);
        proto_send_msg(fd, CMD_FILEOPS, buf, 3 + al);
        client_print_response();
        io_print(1, "\n");

    } else {
        /* Default: exec the command name as-is */
        int al = pm_strlen(cmd);
        char buf[65536];
        buf[0] = al >> 8; buf[1] = al & 0xFF;
        pm_memcpy(buf + 2, cmd, al);
        buf[2 + al] = 0;
        proto_send_msg(fd, CMD_EXEC, buf, 3 + al);
        client_print_response();
    }

    io_close(fd);
    io_exit(0);
}

/* === IP parser === */

static uint32_t parse_ip(const char *s) {
    uint32_t ip = 0;
    int octet = 0;
    for (; *s; s++) {
        if (*s == '.') { ip = (ip << 8) | octet; octet = 0; }
        else octet = octet * 10 + (*s - '0');
    }
    ip = (ip << 8) | octet;
    return __builtin_bswap32(ip);
}

/* === Entry point === */

void pmash_main(long *stack);

__attribute__((naked)) void _start(void) {
    __asm__("mov %rsp, %rdi\n\tcall pmash_main");
}

void pmash_main(long *stack) {
    int argc = (int)stack[0];
    char **argv = (char**)(stack + 1);

    /* Resolve HOME */
    char **envp = argv + argc + 1;
    const char *home = "/tmp";
    for (char **e = envp; *e; e++) {
        if (pm_memcmp(*e, "HOME=", 5) == 0) { home = *e + 5; break; }
    }
    auth_resolve_paths(home);

    if (argc < 2) {
        io_print(2, "Usage: pmash -h <host> [-p <port>] <cmd> [arg]\n"
                     "       pmash --listen <port>\n"
                     "       pmash --version\n");
        io_exit(1);
    }

    /* Parse args */
    uint32_t host_ip = 0;
    uint16_t port = 8822;
    const char *cmd = 0, *arg = 0;

    for (int i = 1; i < argc; i++) {
        if (!pm_strcmp(argv[i], "--version")) {
            io_print(1, "pmash 0.2.0 (x86_64-c)\n");
            io_exit(0);
        } else if (!pm_strcmp(argv[i], "--listen") && i+1 < argc) {
            server_run(pm_atoi(argv[++i]));
            io_exit(0);
        } else if (!pm_strcmp(argv[i], "--daemon") && i+1 < argc) {
            long pid = sys1(SYS_FORK, 0);
            if (pid > 0) io_exit(0);
            if (pid == 0) { sys1(SYS_SETSID, 0); server_run(pm_atoi(argv[++i])); }
            io_exit(0);
        } else if (!pm_strcmp(argv[i], "-h") && i+1 < argc) {
            host_ip = parse_ip(argv[++i]);
        } else if (!pm_strcmp(argv[i], "-p") && i+1 < argc) {
            port = pm_atoi(argv[++i]);
        } else if (!cmd) {
            cmd = argv[i];
        } else if (!arg) {
            arg = argv[i];
        }
    }

    if (!host_ip || !cmd) {
        io_print(2, "Error: -h <host> and command required\n");
        io_exit(1);
    }

    client_run(host_ip, port, cmd, arg);
}
