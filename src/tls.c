/* tls.c — TLS via BearSSL (optional, linked when available)
 *
 * When compiled with -DHAS_TLS and linked with libbearssl.a:
 * - Server: protocol detection (first byte 0x16 → TLS handshake)
 * - Client: TLS when server supports it
 * - Cert/key from $HOME/.pmash/tls/{cert,key}.der
 *
 * Without -DHAS_TLS: all functions are no-ops, binary stays ~18KB.
 */
#include "sys.h"

#ifdef HAS_TLS

#include "bearssl.h"

/* Libc stubs for BearSSL */
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
int getentropy(void *buf, unsigned long len) {
    long r = sys3(SYS_GETRANDOM, (long)buf, (long)len, 0);
    return (r == (long)len) ? 0 : -1;
}
long time(long *t) { if (t) *t = 0; return 0; }

/* BearSSL I/O callbacks */
static int sock_read(void *ctx, unsigned char *buf, size_t len) {
    int r = (int)io_read(*(int*)ctx, buf, len);
    return (r <= 0) ? -1 : r;
}
static int sock_write(void *ctx, const unsigned char *buf, size_t len) {
    int r = (int)io_write(*(int*)ctx, buf, len);
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

/* Server cert+key */
static unsigned char cert_buf[4096], key_buf[256];
static size_t cert_len, key_len;
static br_x509_certificate chain[1];
static br_ec_private_key ec_key;
static char tls_cert_path[200], tls_key_path[200];
static int cert_loaded = 0;

static void build_tls_paths(const char *home) {
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
    if (cert_len <= 0) return -1;
    chain[0].data = cert_buf; chain[0].data_len = cert_len;
    fd = io_open(tls_key_path, 0);
    if (fd < 0) return -1;
    key_len = io_read(fd, key_buf, sizeof(key_buf)); io_close(fd);
    if (key_len <= 0) return -1;
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
    if (is_server) {
        if (!tls_active_s) return;
        br_sslio_close(&ioc_s);
        tls_active_s = 0;
    } else {
        if (!tls_active_c) return;
        br_sslio_close(&ioc_c);
        tls_active_c = 0;
    }
}

/* Called from main to set up paths */
void tls_init(const char *home) {
    build_tls_paths(home);
}

/* Server: check if first byte is 0x16 (TLS) and cert exists */
int tls_server_should_try(int fd) {
    if (load_cert_key() < 0) return 0;
    char peek;
    long r = sys6(SYS_RECVFROM, fd, (long)&peek, 1, 2/*MSG_PEEK*/, 0, 0);
    return (r == 1 && peek == 0x16) ? 1 : 0;
}

#else /* !HAS_TLS */

/* Stubs when TLS not linked */
int tls_client_connect(int fd) { (void)fd; return -1; }
int tls_server_accept(int fd) { (void)fd; return -1; }
int tls_read(int s, void *b, int l) { (void)s;(void)b;(void)l; return -1; }
int tls_write(int s, const void *b, int l) { (void)s;(void)b;(void)l; return -1; }
void tls_close_session(int s) { (void)s; }
void tls_init(const char *h) { (void)h; }
int tls_server_should_try(int fd) { (void)fd; return 0; }

#endif /* HAS_TLS */
