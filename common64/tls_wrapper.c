/* tls_wrapper.c — Minimal TLS wrapper for pmash using BearSSL (no libc)
 *
 * Provides: tls_client_init, tls_server_init, tls_read, tls_write, tls_close
 * Uses inline syscalls (same pattern as ed25519_linux64.c).
 * BearSSL handles: TLS 1.2/1.3 handshake, ChaCha20-Poly1305, X25519, TOFU certs.
 */

#include "bearssl.h"

/* === Inline syscalls (no libc) === */

static long _sys3(long nr, long a, long b, long c) {
    long ret;
    register long r10 __asm__("r10") = 0;
    __asm__ volatile("syscall"
        : "=a"(ret) : "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10)
        : "rcx", "r11", "memory");
    return ret;
}
static long _sys2(long nr, long a, long b) {
    long ret;
    __asm__ volatile("syscall"
        : "=a"(ret) : "a"(nr), "D"(a), "S"(b)
        : "rcx", "r11", "memory");
    return ret;
}
static long _sys1(long nr, long a) {
    long ret;
    __asm__ volatile("syscall"
        : "=a"(ret) : "a"(nr), "D"(a)
        : "rcx", "r11", "memory");
    return ret;
}

#define SYS_READ  0
#define SYS_WRITE 1
#define SYS_OPEN  2
#define SYS_CLOSE 3

/* === Minimal libc replacements for BearSSL === */

void *memmove(void *d, const void *s, unsigned long n) {
    unsigned char *dd = d;
    const unsigned char *ss = s;
    if (dd < ss) {
        while (n--) *dd++ = *ss++;
    } else {
        dd += n; ss += n;
        while (n--) *--dd = *--ss;
    }
    return d;
}

unsigned long strlen(const char *s) {
    unsigned long n = 0;
    while (s[n]) n++;
    return n;
}

int memcmp(const void *a, const void *b, unsigned long n) {
    const unsigned char *aa = a, *bb = b;
    while (n--) {
        if (*aa != *bb) return *aa - *bb;
        aa++; bb++;
    }
    return 0;
}

/* memcpy and memset provided by ed25519_linux64.c */
extern void *memcpy(void *d, const void *s, unsigned long n);
extern void *memset(void *d, int c, unsigned long n);

/* === Libc stubs for BearSSL === */

#define SYS_TIME 201
#define SYS_GETRANDOM 318

/* errno stub */
static int _errno_val = 0;
int *__errno_location(void) { return &_errno_val; }

/* open/read/close — syscall wrappers (BearSSL sysrng uses them) */
int open(const char *path, int flags, ...) {
    return (int)_sys2(SYS_OPEN, (long)path, flags);
}
long read(int fd, void *buf, unsigned long count) {
    return _sys3(SYS_READ, fd, (long)buf, (long)count);
}
int close(int fd) {
    return (int)_sys1(SYS_CLOSE, fd);
}

/* getentropy — Linux 3.17+ */
int getentropy(void *buf, unsigned long len) {
    long r = _sys3(SYS_GETRANDOM, (long)buf, (long)len, 0);
    return (r == (long)len) ? 0 : -1;
}

/* time — for X.509 cert validation (TOFU doesn't need it, but symbol required) */
long time(long *t) {
    /* Return 0 — we don't validate cert dates (TOFU) */
    if (t) *t = 0;
    return 0;
}

/* === BearSSL I/O callbacks === */

/* Low-level socket read: BearSSL calls this to receive data from socket */
static int sock_read(void *ctx, unsigned char *buf, size_t len) {
    int fd = *(int *)ctx;
    long r = _sys3(SYS_READ, fd, (long)buf, (long)len);
    if (r < 0) return -1;
    if (r == 0) return -1;  /* EOF */
    return (int)r;
}

/* Low-level socket write: BearSSL calls this to send data to socket */
static int sock_write(void *ctx, const unsigned char *buf, size_t len) {
    int fd = *(int *)ctx;
    long r = _sys3(SYS_WRITE, fd, (long)buf, (long)len);
    if (r < 0) return -1;
    return (int)r;
}

/* === TLS context structures === */

/* Static buffers — no malloc needed */
static unsigned char iobuf_client[BR_SSL_BUFSIZE_BIDI];
static unsigned char iobuf_server[BR_SSL_BUFSIZE_BIDI];
static br_ssl_client_context cc;
static br_ssl_server_context sc;
static br_x509_minimal_context xc;
static br_sslio_context ioc_client;
static br_sslio_context ioc_server;
static int client_fd_storage;
static int server_fd_storage;

/* Server certificate + private key (loaded from files) */
static unsigned char server_cert_buf[4096];
static size_t server_cert_len = 0;
static unsigned char server_key_buf[256];
static size_t server_key_len = 0;
static br_x509_certificate server_chain[1];
static br_ec_private_key server_ec_key;

/* TOFU X.509 validator: accepts everything */
static void xwc_start_chain(const br_x509_class **ctx, const char *server_name) {
    (void)ctx; (void)server_name;
}
static void xwc_start_cert(const br_x509_class **ctx, unsigned int length) {
    (void)ctx; (void)length;
}
static void xwc_append(const br_x509_class **ctx, const unsigned char *buf, size_t len) {
    (void)ctx; (void)buf; (void)len;
}
static void xwc_end_cert(const br_x509_class **ctx) {
    (void)ctx;
}
static unsigned xwc_end_chain(const br_x509_class **ctx) {
    (void)ctx;
    return 0;  /* Always trust (TOFU) */
}
static const br_x509_pkey *xwc_get_pkey(const br_x509_class *const *ctx, unsigned *usages) {
    (void)ctx;
    if (usages) *usages = BR_KEYTYPE_EC | BR_KEYTYPE_SIGN;
    /* Return NULL — we skip cert verification entirely for TOFU */
    return 0;
}

static const br_x509_class xwc_vtable = {
    sizeof(br_x509_class *),
    xwc_start_chain,
    xwc_start_cert,
    xwc_append,
    xwc_end_cert,
    xwc_end_chain,
    xwc_get_pkey
};

/* X.509 context for TOFU */
static const br_x509_class *xwc_ctx = &xwc_vtable;

/* === Key generation (self-signed EC key) === */

static unsigned char ec_privkey[32];
static unsigned char ec_pubkey[65];  /* uncompressed P-256 point */
static int keys_generated = 0;

static void generate_ec_key(void) {
    if (keys_generated) return;
    /* Read random bytes for private key */
    long fd = _sys2(SYS_OPEN, (long)"/dev/urandom", 0);
    if (fd >= 0) {
        _sys3(SYS_READ, fd, (long)ec_privkey, 32);
        _sys1(SYS_CLOSE, fd);
    }
    keys_generated = 1;
}

/* === Public API called from ASM === */

/*
 * tls_client_connect(int fd) → 0 = success, -1 = fail
 * Performs TLS handshake as client on already-connected socket.
 */
int tls_client_connect(int fd) {
    client_fd_storage = fd;

    /* Init client with TOFU validator (accept any cert) */
    br_ssl_client_init_full(&cc, &xc, 0, 0);

    /* Replace X.509 validator with our TOFU one */
    br_ssl_engine_set_x509(&cc.eng, &xwc_ctx);

    /* Set I/O buffer */
    br_ssl_engine_set_buffer(&cc.eng, iobuf_client, sizeof(iobuf_client), 1);

    /* Reset and start handshake */
    br_ssl_client_reset(&cc, "pmash", 0);

    /* Set up I/O wrapper */
    br_sslio_init(&ioc_client, &cc.eng, sock_read, &client_fd_storage,
                  sock_write, &client_fd_storage);

    /* Force handshake by flushing */
    br_sslio_flush(&ioc_client);

    /* Check for error */
    if (br_ssl_engine_current_state(&cc.eng) == BR_SSL_CLOSED) {
        return -1;
    }

    return 0;
}

/*
 * tls_server_accept(int fd) → 0 = success, -1 = fail
 * Performs TLS handshake as server on accepted socket.
 * Uses ephemeral EC key (no certificate files needed for TOFU).
 */
/* Path buffer filled by ASM (server.inc builds from $HOME/.pmash/) */
extern unsigned char _tls_cert_path_buf[200];

/* Load server cert+key — cert path from _tls_cert_path_buf,
 * key path = same dir + "key.der" */
static int load_server_cert_key(void) {
    if (server_cert_len > 0) return 0;  /* already loaded */

    /* Read cert from _tls_cert_path_buf (already built by ASM) */
    long fd = _sys2(SYS_OPEN, (long)_tls_cert_path_buf, 0);
    if (fd < 0) return -1;
    long r = _sys3(SYS_READ, fd, (long)server_cert_buf, sizeof(server_cert_buf));
    _sys1(SYS_CLOSE, fd);
    if (r <= 0) return -1;
    server_cert_len = (size_t)r;

    server_chain[0].data = server_cert_buf;
    server_chain[0].data_len = server_cert_len;

    /* Build key path: replace "cert.der" with "key.der" in path */
    static char key_path[200];
    unsigned long plen = strlen((const char *)_tls_cert_path_buf);
    memcpy(key_path, _tls_cert_path_buf, plen + 1);
    /* Find last '/' and replace filename */
    int i;
    for (i = (int)plen - 1; i >= 0; i--) {
        if (key_path[i] == '/') {
            key_path[i+1] = 'k'; key_path[i+2] = 'e'; key_path[i+3] = 'y';
            key_path[i+4] = '.'; key_path[i+5] = 'd'; key_path[i+6] = 'e';
            key_path[i+7] = 'r'; key_path[i+8] = 0;
            break;
        }
    }

    fd = _sys2(SYS_OPEN, (long)key_path, 0);
    if (fd < 0) return -1;
    r = _sys3(SYS_READ, fd, (long)server_key_buf, sizeof(server_key_buf));
    _sys1(SYS_CLOSE, fd);
    if (r <= 0) return -1;
    server_key_len = (size_t)r;

    server_ec_key.curve = BR_EC_secp256r1;
    server_ec_key.x = server_key_buf;
    server_ec_key.xlen = server_key_len;

    return 0;
}

int tls_server_accept(int fd) {
    server_fd_storage = fd;

    /* Load cert+key from files (first call loads, subsequent reuse) */
    if (load_server_cert_key() < 0) {
        /* No cert — TLS not available, return -1 (caller falls back to plain) */
        return -1;
    }

    /* Init server with EC cert + key */
    br_ssl_server_init_full_ec(&sc, server_chain, 1,
                                BR_KEYTYPE_EC,
                                &server_ec_key);

    br_ssl_engine_set_buffer(&sc.eng, iobuf_server, sizeof(iobuf_server), 1);

    br_ssl_server_reset(&sc);

    br_sslio_init(&ioc_server, &sc.eng, sock_read, &server_fd_storage,
                  sock_write, &server_fd_storage);

    /* Drive handshake */
    br_sslio_flush(&ioc_server);

    if (br_ssl_engine_current_state(&sc.eng) == BR_SSL_CLOSED) {
        return -1;
    }

    return 0;
}

/*
 * tls_read(int is_server, void *buf, int len) → bytes read, -1 on error
 */
int tls_read(int is_server, void *buf, int len) {
    br_sslio_context *ioc = is_server ? &ioc_server : &ioc_client;
    int r = br_sslio_read(ioc, buf, len);
    return r;
}

/*
 * tls_write(int is_server, const void *buf, int len) → bytes written, -1 on error
 */
int tls_write(int is_server, const void *buf, int len) {
    br_sslio_context *ioc = is_server ? &ioc_server : &ioc_client;
    int r = br_sslio_write(ioc, buf, len);
    if (r >= 0) {
        br_sslio_flush(ioc);
    }
    return r;
}

/*
 * tls_close(int is_server) — close TLS session
 */
void tls_close(int is_server) {
    br_sslio_context *ioc = is_server ? &ioc_server : &ioc_client;
    br_sslio_close(ioc);
}
