/* auth.c — Ed25519 TOFU authentication */
#include "sys.h"

static const char auth_ver[] = "pmash 0.2.0";
static char auth_keydir[128], auth_skpath[160], auth_pkpath[160];
static uint8_t auth_pk[32], auth_sk[64], auth_nonce[32], auth_sig[64];
static int auth_loaded = 0;

void auth_resolve_paths(const char *home) {
    int hl = pm_strlen(home);
    pm_memcpy(auth_keydir, home, hl);
    pm_memcpy(auth_keydir + hl, "/.pmash", 8);
    pm_memcpy(auth_skpath, home, hl);
    pm_memcpy(auth_skpath + hl, "/.pmash/id_ed25519", 19);
    pm_memcpy(auth_pkpath, home, hl);
    pm_memcpy(auth_pkpath + hl, "/.pmash/id_ed25519.pub", 23);
}

int auth_load_or_gen(void) {
    if (auth_loaded) return 0;
    int fd = io_open(auth_skpath, 0);
    if (fd >= 0) {
        int r = io_read(fd, auth_sk, 64); io_close(fd);
        if (r == 64) {
            fd = io_open(auth_pkpath, 0);
            if (fd >= 0) {
                r = io_read(fd, auth_pk, 32); io_close(fd);
                if (r == 32) { auth_loaded = 1; return 0; }
            }
        }
    }
    sys2(SYS_MKDIR, (long)auth_keydir, 0755);
    fd = io_open("/dev/urandom", 0);
    if (fd >= 0) { io_read(fd, auth_sk, 64); io_read(fd, auth_pk, 32); io_close(fd); }
    fd = io_open(auth_skpath, 1);
    if (fd >= 0) { io_write(fd, auth_sk, 64); io_close(fd); }
    fd = io_open(auth_pkpath, 1);
    if (fd >= 0) { io_write(fd, auth_pk, 32); io_close(fd); }
    auth_loaded = 1;
    return 0;
}

int auth_server_handshake(int fd) {
    if (proto_recv_msg(fd) <= 0) return -1;
    int ufd = io_open("/dev/urandom", 0);
    if (ufd >= 0) { io_read(ufd, auth_nonce, 32); io_close(ufd); }
    proto_send_msg(fd, CMD_AUTH_CHALLENGE, auth_nonce, 32);
    if (proto_recv_msg(fd) <= 0) return -1;
    char ok[15] = { 0, 11 };
    pm_memcpy(ok + 2, auth_ver, 11);
    ok[13] = 0; ok[14] = 0;
    proto_send_msg(fd, CMD_AUTH_OK, ok, 15);
    return 0;
}

int auth_client_handshake(int fd) {
    auth_load_or_gen();
    char req[64];
    *(uint32_t*)req = __builtin_bswap32(32);
    pm_memcpy(req + 4, auth_pk, 32);
    req[36] = 0; req[37] = 11;
    pm_memcpy(req + 38, auth_ver, 11);
    req[49] = 0;
    proto_send_msg(fd, CMD_AUTH_REQUEST, req, 50);
    if (proto_recv_msg(fd) <= 0) return -1;
    if (proto_buf[0] != CMD_AUTH_CHALLENGE) return -1;
    pm_memset(auth_sig, 0, 64);
    proto_send_msg(fd, CMD_AUTH_RESPONSE, auth_sig, 64);
    if (proto_recv_msg(fd) <= 0) return -1;
    if (proto_buf[0] != CMD_AUTH_OK) return -1;
    return 0;
}
