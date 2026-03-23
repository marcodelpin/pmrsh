/* sys_vtable.h — Header for vtable-based unified build
 * Replaces sys.h when building the single-binary APE.
 * All I/O functions are extern (provided by vtable_rt.c).
 */
#ifndef PMASH_SYS_VTABLE_H
#define PMASH_SYS_VTABLE_H

typedef unsigned long  size_t;
typedef long           ssize_t;
typedef unsigned short uint16_t;
typedef unsigned int   uint32_t;
typedef unsigned long  uint64_t;
typedef int            int32_t;
typedef unsigned char  uint8_t;

/* These are NOT inline — they dispatch through the vtable in vtable_rt.c */
extern ssize_t io_write(int fd, const void *buf, size_t len);
extern ssize_t io_read(int fd, void *buf, size_t len);
extern int     io_open(const char *path, int flags);
extern int     io_close(int fd);
extern long    io_seek(int fd, long off, int whence);
extern long    io_filesize(int fd);
extern void    io_exit(int code);
extern void    io_print(int fd, const char *s);
extern int     io_exec(const char *cmd, char *outbuf, int outbufsize);
extern void    io_sleep_ms(int ms);
extern int     io_hostname(char *buf, int len);
extern int     net_socket(void);
extern int     net_connect(int fd, uint32_t ip, uint16_t port);
extern int     net_bind(int fd, uint16_t port);
extern int     net_listen(int fd, int backlog);
extern int     net_accept(int fd);

/* Init — call at startup before anything else */
extern int  detect_os(void);
extern void patch_vtable(void);
extern int  os_type;

/* vtable also exposes send/recv for proto.c */
typedef struct {
    ssize_t (*write)(int, const void*, size_t);
    ssize_t (*read)(int, void*, size_t);
    int (*open)(const char*, int);
    int (*close)(int);
    long (*seek)(int, long, int);
    long (*filesize)(int);
    int (*rename)(const char*, const char*);
    int (*unlink)(const char*);
    int (*mkdir)(const char*);
    int (*socket)(void);
    int (*connect)(int, uint32_t, uint16_t);
    int (*bind)(int, uint16_t);
    int (*listen)(int, int);
    int (*accept)(int);
    int (*send)(int, const void*, size_t);
    int (*recv)(int, void*, size_t);
    int (*exec)(const char*, char*, int);
    void (*exit_)(int);
    void (*sleep_ms)(int);
    int (*hostname)(char*, int);
    int (*getpid)(void);
    int (*poll)(int, int);
} os_vtable_t;
extern os_vtable_t vt;

/* Syscall stubs for code that references them (relay.c, system.c) */
static inline long sys1(long n,long a){(void)n;(void)a;return -1;}
static inline long sys2(long n,long a,long b){(void)n;(void)a;(void)b;return -1;}
static inline long sys3(long n,long a,long b,long c){(void)n;(void)a;(void)b;(void)c;return -1;}
static inline long sys4(long n,long a,long b,long c,long d){(void)n;(void)a;(void)b;(void)c;(void)d;return -1;}
static inline long sys5(long n,long a,long b,long c,long d,long e){(void)n;(void)a;(void)b;(void)c;(void)d;(void)e;return -1;}
static inline long sys6(long n,long a,long b,long c,long d,long e,long f){(void)n;(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;return -1;}
#define SYS_MKDIR 0
#define SYS_UNLINK 0
#define SYS_RENAME 0
#define SYS_FORK 0
#define SYS_SETSID 0
#define SYS_KILL 0
#define SYS_READLINK 0
#define SYS_SENDTO 0
#define SYS_RECVFROM 0
#define SYS_GETRANDOM 0
#define SYS_POLL 0
#define SYS_OPEN 0
#define SYS_CLOSE 0
#define SYS_FSTAT 0
#define SYS_SOCKET 0
#define SYS_ACCEPT 0
#define SYS_CONNECT 0
#define SYS_BIND 0
#define SYS_LISTEN 0
#define SYS_SETSOCKOPT 0
#define SYS_READ 0
#define SYS_WRITE 0
#define SYS_LSEEK 0
#define SYS_BRK 0
#define SYS_NANOSLEEP 0
#define SYS_GETPID 0
#define SYS_PIPE 0
#define SYS_DUP2 0
#define SYS_WAIT4 0
#define SYS_EXECVE 0
#define SYS_EXIT 0

#define POLLIN 1
#define SEEK_SET 0
#define SIGKILL 9
#define AF_INET 2
#define SOCK_STREAM 1
#define SOCK_DGRAM 2
#define SOL_SOCKET 1
#define SO_REUSEADDR 2
#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#define O_CREAT 64
#define O_TRUNC 512

struct sockaddr_in { uint16_t family; uint16_t port; uint32_t addr; uint64_t zero; };

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

#define SYNC_BLOCK_SIZE 4096
#define DELTA_MATCH 'M'
#define DELTA_DATA 'D'
#define DELTA_END 'E'

/* Shared buffers */
extern char proto_buf[65536];
extern char proto_hdr[4];
extern char srv_execbuf[65536];
extern char srv_filebuf[32768];
extern char srv_infobuf[512];
extern char srv_hostbuf[256];
extern uint8_t sync_blockbuf[SYNC_BLOCK_SIZE];
extern uint8_t sync_sigbuf[65536];
extern int srv_client;

/* Function declarations (same as sys.h) */
size_t pm_strlen(const char *s);
void  *pm_memcpy(void *d, const void *s, size_t n);
void  *pm_memset(void *d, int c, size_t n);
int    pm_memcmp(const void *a, const void *b, size_t n);
int    pm_strcmp(const char *a, const char *b);
int    pm_atoi(const char *s);
int    proto_send_all(int fd, const void *buf, int len);
int    proto_recv_all(int fd, void *buf, int len);
int    proto_send_msg(int fd, uint8_t cmd, const void *payload, int plen);
int    proto_recv_msg(int fd);
void   auth_resolve_paths(const char *home);
int    auth_load_or_gen(void);
int    auth_server_handshake(int fd);
int    auth_client_handshake(int fd);
int    safety_check(const char *cmd);
void   rl_check(void);
void   rl_fail(void);
void   rl_success(void);
uint32_t adler32(const uint8_t *data, size_t len);
int    sync_compute_sigs(int fd);
void   sync_send_delta(int net_fd, int file_fd, const uint8_t *sigs, int sig_count);
int    sync_apply_delta(int net_fd, int local_fd, int out_fd);
void   proxy_forward(int fd_a, int fd_b);
void   tunnel_handle(int client_fd);
int    rle_compress(const uint8_t *in, int inlen, uint8_t *out);
int    rle_decompress(const uint8_t *in, int inlen, uint8_t *out);
void   server_run(uint16_t port);
void   client_run(uint32_t ip, uint16_t port, const char *cmd, const char *arg);
void   tls_init(const char *home);
int    tls_server_should_try(int fd);
int    tls_client_connect(int fd);
int    tls_server_accept(int fd);
void   tls_close_session(int is_server);
void   config_init(const char *home);
int    config_lookup(const char *name, uint32_t *ip, uint16_t *port, char *mac);
void   system_handle(int cfd);
int    wol_send(const char *mac_str);
int    wol_by_name(const char *name);
void   session_handle(int cfd);
int    batch_exec(int server_fd, const char *script_path);
void   known_hosts_init(const char *home);
void   fleet_status(void);
uint32_t parse_ip(const char *s);

#define PMASH_SYS_H /* prevent sys.h from being included */
#endif
