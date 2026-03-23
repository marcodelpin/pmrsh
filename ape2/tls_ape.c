/* tls_ape.c — TLS via BearSSL for vtable APE build
 * Same as src/tls.c but uses vtable I/O instead of sys3/sys.h
 */
#include "sys_vtable.h"

#ifdef HAS_TLS

#include "bearssl.h"

/* Libc stubs for BearSSL — use vtable I/O */
void *memcpy(void *d, const void *s, unsigned long n) { return pm_memcpy(d, s, n); }
void *memset(void *d, int c, unsigned long n) { return pm_memset(d, c, n); }
void *memmove(void *d, const void *s, unsigned long n) {
    char *dd = d; const char *ss = s;
    if (dd < ss) { while (n--) *dd++ = *ss++; }
    else { dd += n; ss += n; while (n--) *--dd = *--ss; }
    return d;
}
int memcmp(const void *a, const void *b, unsigned long n) { return pm_memcmp(a, b, n); }
unsigned long strlen(const char *s) { return pm_strlen(s); }
int *__errno_location(void) { static int e = 0; return &e; }
int open(const char *p, int f, ...) { return io_open(p, f == 0 ? 0 : 1); }
long read(int fd, void *b, unsigned long n) { return io_read(fd, b, n); }
int close(int fd) { return io_close(fd); }
long time(long *t) { if (t) *t = 0; return 0; }

/* getentropy — vtable-aware: Linux uses getrandom syscall, Windows uses BCryptGenRandom */
int getentropy(void *buf, unsigned long len) {
    if (os_type == 1) {
        /* Linux: SYS_GETRANDOM = 318 */
        long r;
        register long r10 __asm__("r10") = 0;
        __asm__ volatile("syscall":"=a"(r):"a"(318L),"D"((long)buf),"S"((long)len),"d"(0L),"r"(r10):"rcx","r11","memory");
        return (r == (long)len) ? 0 : -1;
    } else {
        /* Windows: read from urandom-equivalent via CryptGenRandom or RtlGenRandom */
        /* RtlGenRandom is in advapi32.dll, exported as SystemFunction036 */
        extern void *find_module(const char *);
        extern void *find_export(void *, const char *);
        void *advapi = find_module("advapi32.dll");
        if (!advapi) {
            /* Try loading it */
            void *k32 = find_module("kernel32.dll");
            void* __attribute__((ms_abi)) (*pLoad)(const char*) = find_export(k32, "LoadLibraryA");
            if (pLoad) advapi = pLoad("advapi32.dll");
        }
        if (advapi) {
            int __attribute__((ms_abi)) (*pRtlGenRandom)(void*, unsigned long) =
                find_export(advapi, "SystemFunction036");
            if (pRtlGenRandom) return pRtlGenRandom(buf, len) ? 0 : -1;
        }
        return -1;
    }
}

/* BearSSL I/O callbacks — use vtable */
static int sock_read(void *ctx, unsigned char *buf, size_t len) {
    int r = (int)vt.recv(*(int*)ctx, buf, len);
    return (r <= 0) ? -1 : r;
}
static int sock_write(void *ctx, const unsigned char *buf, size_t len) {
    int r = (int)vt.send(*(int*)ctx, buf, len);
    return (r <= 0) ? -1 : r;
}

/* Static state */
static int tls_active_c = 0, tls_active_s = 0;
static unsigned char iobuf_c[BR_SSL_BUFSIZE_BIDI];
static unsigned char iobuf_s[BR_SSL_BUFSIZE_BIDI];
static br_ssl_client_context cc;
static br_ssl_server_context sc;
static br_x509_minimal_context xc;
static br_sslio_context ioc_c, ioc_s;
static int fd_c, fd_s;

/* TOFU X.509 — accept everything */
static void xwc_start(const br_x509_class **c, const char *n) { (void)c;(void)n; }
static void xwc_scert(const br_x509_class **c, unsigned l) { (void)c;(void)l; }
static void xwc_append(const br_x509_class **c, const unsigned char *b, size_t l) { (void)c;(void)b;(void)l; }
static void xwc_ecert(const br_x509_class **c) { (void)c; }
static unsigned xwc_echain(const br_x509_class **c) { (void)c; return 0; }
static const br_x509_pkey *xwc_pkey(const br_x509_class *const *c, unsigned *u) {
    (void)c; if (u) *u = BR_KEYTYPE_EC | BR_KEYTYPE_SIGN; return 0;
}
static const br_x509_class xwc_vt = {
    sizeof(br_x509_class*), xwc_start, xwc_scert, xwc_append, xwc_ecert, xwc_echain, xwc_pkey
};
static const br_x509_class *xwc = &xwc_vt;

/* Server cert/key */
static unsigned char cert_buf[4096], key_buf[256];
static size_t cert_len, key_len;
static br_x509_certificate chain[1];
static br_ec_private_key ec_key;
static char tls_cert_path[200], tls_key_path[200];
static int cert_loaded = 0;

void tls_init(const char *home) {
    int hl = pm_strlen(home);
    pm_memcpy(tls_cert_path, home, hl);
    pm_memcpy(tls_cert_path + hl, "/.pmash/tls/cert.der", 21);
    pm_memcpy(tls_key_path, home, hl);
    pm_memcpy(tls_key_path + hl, "/.pmash/tls/key.der", 20);
}

static int load_cert_key(void) {
    if (cert_loaded) return cert_len > 0 ? 0 : -1;
    cert_loaded = 1;
    int fd = io_open(tls_cert_path, 0);
    if (fd < 0) return -1;
    cert_len = io_read(fd, cert_buf, sizeof(cert_buf)); io_close(fd);
    if ((ssize_t)cert_len <= 0) return -1;
    chain[0].data = cert_buf; chain[0].data_len = cert_len;
    fd = io_open(tls_key_path, 0);
    if (fd < 0) return -1;
    key_len = io_read(fd, key_buf, sizeof(key_buf)); io_close(fd);
    if ((ssize_t)key_len <= 0) return -1;
    ec_key.curve = BR_EC_secp256r1;
    ec_key.x = key_buf; ec_key.xlen = key_len;
    return 0;
}

int tls_client_connect(int fd) {
    fd_c = fd;
    br_ssl_client_init_full(&cc, &xc, 0, 0);
    br_ssl_engine_set_x509(&cc.eng, &xwc);
    br_ssl_engine_set_buffer(&cc.eng, iobuf_c, sizeof(iobuf_c), 1);
    br_ssl_client_reset(&cc, "pmash", 0);
    br_sslio_init(&ioc_c, &cc.eng, sock_read, &fd_c, sock_write, &fd_c);
    br_sslio_flush(&ioc_c);
    if (br_ssl_engine_current_state(&cc.eng) == BR_SSL_CLOSED) return -1;
    tls_active_c = 1;
    return 0;
}

int tls_server_accept(int fd) {
    fd_s = fd;
    if (load_cert_key() < 0) return -1;
    br_ssl_server_init_full_ec(&sc, chain, 1, BR_KEYTYPE_EC, &ec_key);
    br_ssl_engine_set_buffer(&sc.eng, iobuf_s, sizeof(iobuf_s), 1);
    br_ssl_server_reset(&sc);
    br_sslio_init(&ioc_s, &sc.eng, sock_read, &fd_s, sock_write, &fd_s);
    br_sslio_flush(&ioc_s);
    if (br_ssl_engine_current_state(&sc.eng) == BR_SSL_CLOSED) return -1;
    tls_active_s = 1;
    return 0;
}

int tls_read(int is_server, void *buf, int len) {
    return br_sslio_read(is_server ? &ioc_s : &ioc_c, buf, len);
}
int tls_write(int is_server, const void *buf, int len) {
    br_sslio_context *ioc = is_server ? &ioc_s : &ioc_c;
    int r = br_sslio_write(ioc, buf, len);
    if (r >= 0) br_sslio_flush(ioc);
    return r;
}
void tls_close_session(int is_server) {
    if (is_server) { if (!tls_active_s) return; br_sslio_close(&ioc_s); tls_active_s = 0; }
    else { if (!tls_active_c) return; br_sslio_close(&ioc_c); tls_active_c = 0; }
}
int tls_server_should_try(int fd) {
    if (load_cert_key() < 0) return 0;
    /* Peek first byte — use vtable recv with MSG_PEEK */
    char peek;
    if (os_type == 1) {
        /* Linux: recvfrom with MSG_PEEK */
        long r;
        register long r10 __asm__("r10") = 2; /* MSG_PEEK */
        register long r8 __asm__("r8") = 0;
        register long r9 __asm__("r9") = 0;
        __asm__ volatile("syscall":"=a"(r):"a"(45L),"D"((long)fd),"S"((long)&peek),"d"(1L),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");
        return (r == 1 && peek == 0x16) ? 1 : 0;
    }
    /* Windows: recv with MSG_PEEK — TODO */
    return 0;
}

#else /* !HAS_TLS */

void tls_init(const char *h) { (void)h; }
int  tls_server_should_try(int fd) { (void)fd; return 0; }
int  tls_client_connect(int fd) { (void)fd; return -1; }
int  tls_server_accept(int fd) { (void)fd; return -1; }
int  tls_read(int s, void *b, int l) { (void)s;(void)b;(void)l; return -1; }
int  tls_write(int s, const void *b, int l) { (void)s;(void)b;(void)l; return -1; }
void tls_close_session(int s) { (void)s; }

#endif
