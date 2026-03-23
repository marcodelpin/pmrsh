/* sys.h — Types, syscall wrappers, constants (no libc)
 * Part of pmash — lightweight remote agent
 */
#ifndef PMASH_SYS_H
#define PMASH_SYS_H

typedef unsigned long  size_t;
typedef long           ssize_t;
typedef unsigned short uint16_t;
typedef unsigned int   uint32_t;
typedef unsigned long  uint64_t;
typedef int            int32_t;
typedef unsigned char  uint8_t;

/* === Inline syscall wrappers === */

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

/* === Syscall numbers (x86_64 Linux) === */

#define SYS_READ       0
#define SYS_WRITE      1
#define SYS_OPEN       2
#define SYS_CLOSE      3
#define SYS_FSTAT      5
#define SYS_POLL       7
#define SYS_LSEEK      8
#define SYS_BRK        12
#define SYS_PIPE       22
#define SYS_DUP2       33
#define SYS_NANOSLEEP  35
#define SYS_GETPID     39
#define SYS_SOCKET     41
#define SYS_CONNECT    42
#define SYS_ACCEPT     43
#define SYS_SENDTO     44
#define SYS_RECVFROM   45
#define SYS_BIND       49
#define SYS_LISTEN     50
#define SYS_SETSOCKOPT 54
#define SYS_FORK       57
#define SYS_EXECVE     59
#define SYS_EXIT       60
#define SYS_WAIT4      61
#define SYS_KILL       62
#define SYS_RENAME     82
#define SYS_MKDIR      83
#define SYS_UNLINK     87
#define SYS_READLINK   89
#define SYS_SETSID     112
#define SYS_GETRANDOM  318

/* === Constants === */

#define AF_INET      2
#define SOCK_STREAM  1
#define SOCK_DGRAM   2
#define SOL_SOCKET   1
#define SO_REUSEADDR 2
#define O_RDONLY     0
#define O_WRONLY     1
#define O_RDWR       2
#define O_CREAT      64
#define O_TRUNC      512
#define POLLIN       1
#define SEEK_SET     0
#define SIGKILL      9

/* === Protocol command IDs === */

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
#define CMD_SELF_UPDATE_OK  0x71
#define CMD_SHELL_REQ       0x80
#define CMD_SHELL_DATA      0x81
#define CMD_SYNC_REQ        0x90
#define CMD_SYNC_RESP       0x91
#define CMD_SYNC_PUSH_REQ   0x92
#define CMD_SYNC_PUSH_SIGS  0x93
#define CMD_SYNC_PUSH_OK    0x95
#define CMD_WRITE           0xA0
#define CMD_WRITE_OK        0xA1
#define CMD_NATIVE          0xB0
#define CMD_NATIVE_RESP     0xB1
#define CMD_FILEOPS         0xB5
#define CMD_FILEOPS_RESP    0xB6
#define CMD_PROXY_CONNECT   0xD0
#define CMD_PROXY_OK        0xD1
#define CMD_TUNNEL_OPEN     0xD5
#define CMD_TUNNEL_OK       0xD6
#define CMD_TUNNEL_FAIL     0xD7
#define CMD_COMPRESS        0xE0
#define CMD_ERROR           0xFF

/* === Sync constants === */

#define SYNC_BLOCK_SIZE 4096
#define DELTA_MATCH     'M'
#define DELTA_DATA      'D'
#define DELTA_END       'E'

/* === Shared buffers (global, no malloc) === */

extern char proto_buf[65536];
extern char proto_hdr[4];
extern char srv_execbuf[65536];
extern char srv_filebuf[32768];
extern char srv_infobuf[512];
extern char srv_hostbuf[256];
extern uint8_t sync_blockbuf[SYNC_BLOCK_SIZE];
extern uint8_t sync_sigbuf[65536];
extern int srv_client;

/* === I/O wrappers === */

static inline ssize_t io_write(int fd, const void *buf, size_t len) {
    return sys3(SYS_WRITE, fd, (long)buf, len);
}
static inline ssize_t io_read(int fd, void *buf, size_t len) {
    return sys3(SYS_READ, fd, (long)buf, len);
}
static inline int io_open(const char *path, int flags) {
    int f = flags;
    if (f == 1) f = O_WRONLY | O_CREAT | O_TRUNC;
    return (int)sys3(SYS_OPEN, (long)path, f, 0644);
}
static inline int io_close(int fd) { return (int)sys1(SYS_CLOSE, fd); }
static inline long io_seek(int fd, long off, int whence) {
    return sys3(SYS_LSEEK, fd, off, whence);
}
static inline void io_exit(int code) {
    sys1(SYS_EXIT, code); __builtin_unreachable();
}
static inline long io_filesize(int fd) {
    char buf[144];
    if (sys2(SYS_FSTAT, fd, (long)buf) < 0) return -1;
    return *(long*)(buf + 48);
}
static inline void io_print(int fd, const char *s) {
    size_t n = 0; while (s[n]) n++;
    io_write(fd, s, n);
}
static inline int net_socket(void) {
    return (int)sys3(SYS_SOCKET, AF_INET, SOCK_STREAM, 0);
}

struct sockaddr_in { uint16_t family; uint16_t port; uint32_t addr; uint64_t zero; };

static inline int net_connect(int fd, uint32_t ip, uint16_t port) {
    struct sockaddr_in sa = { AF_INET, __builtin_bswap16(port), ip, 0 };
    return (int)sys3(SYS_CONNECT, fd, (long)&sa, sizeof(sa));
}
static inline int net_bind(int fd, uint16_t port) {
    int one = 1;
    sys5(SYS_SETSOCKOPT, fd, SOL_SOCKET, SO_REUSEADDR, (long)&one, 4);
    struct sockaddr_in sa = { AF_INET, __builtin_bswap16(port), 0, 0 };
    return (int)sys3(SYS_BIND, fd, (long)&sa, sizeof(sa));
}
static inline int net_listen(int fd, int backlog) {
    return (int)sys2(SYS_LISTEN, fd, backlog);
}
static inline int net_accept(int fd) {
    return (int)sys3(SYS_ACCEPT, fd, 0, 0);
}

/* === Function declarations === */

/* util.c */
size_t pm_strlen(const char *s);
void  *pm_memcpy(void *d, const void *s, size_t n);
void  *pm_memset(void *d, int c, size_t n);
int    pm_memcmp(const void *a, const void *b, size_t n);
int    pm_strcmp(const char *a, const char *b);
int    pm_atoi(const char *s);
int    io_hostname(char *buf, int len);
void   io_sleep_ms(int ms);
int    io_exec(const char *cmd, char *outbuf, int outbufsize);

/* proto.c */
int  proto_send_all(int fd, const void *buf, int len);
int  proto_recv_all(int fd, void *buf, int len);
int  proto_send_msg(int fd, uint8_t cmd, const void *payload, int plen);
int  proto_recv_msg(int fd);

/* auth.c */
void auth_resolve_paths(const char *home);
int  auth_load_or_gen(void);
int  auth_server_handshake(int fd);
int  auth_client_handshake(int fd);

/* safety.c */
int  safety_check(const char *cmd);
void rl_check(void);
void rl_fail(void);
void rl_success(void);

/* sync.c */
uint32_t adler32(const uint8_t *data, size_t len);
int  sync_compute_sigs(int fd);
void sync_send_delta(int net_fd, int file_fd, const uint8_t *sigs, int sig_count);
int  sync_apply_delta(int net_fd, int local_fd, int out_fd);

/* tunnel.c */
void proxy_forward(int fd_a, int fd_b);
void tunnel_handle(int client_fd);

/* compress.c */
int rle_compress(const uint8_t *in, int inlen, uint8_t *out);
int rle_decompress(const uint8_t *in, int inlen, uint8_t *out);

/* server.c */
void server_run(uint16_t port);

/* client.c */
void client_run(uint32_t ip, uint16_t port, const char *cmd, const char *arg);

/* tls.c */
void tls_init(const char *home);
int  tls_server_should_try(int fd);
int  tls_client_connect(int fd);
int  tls_server_accept(int fd);
int  tls_read(int is_server, void *buf, int len);
int  tls_write(int is_server, const void *buf, int len);
void tls_close_session(int is_server);

/* relay.c */
int  relay_register(uint32_t rdv_ip, uint16_t rdv_port, const char *device_id);
int  relay_resolve(uint32_t rdv_ip, uint16_t rdv_port, const char *device_id,
                   uint32_t *out_ip, uint16_t *out_port);

/* IP parser */
uint32_t parse_ip(const char *s);

#endif /* PMASH_SYS_H */
