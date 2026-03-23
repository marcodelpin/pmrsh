/* relay.c — UDP rendezvous for hbbs (RegisterPeer + PunchHoleRequest) */
#include "sys.h"

#define RDV_REGISTER_PEER      6
#define RDV_PUNCH_HOLE_REQUEST 8
#define RDV_PORT               21116

static char rdv_buf[4096];

/* Minimal protobuf varint encoder */
static int pb_varint(uint8_t *buf, uint32_t val) {
    int n = 0;
    while (val > 0x7F) { buf[n++] = (val & 0x7F) | 0x80; val >>= 7; }
    buf[n++] = val & 0x7F;
    return n;
}

/* Write protobuf string field: tag + len + data */
static int pb_string(uint8_t *buf, int field, const void *data, int len) {
    int n = 0;
    n += pb_varint(buf + n, (field << 3) | 2); /* tag: field, wire=2 */
    n += pb_varint(buf + n, len);
    pm_memcpy(buf + n, data, len); n += len;
    return n;
}

static int udp_sendto(int fd, const void *buf, int len, uint32_t ip, uint16_t port) {
    /* Build sockaddr_in manually to avoid platform struct differences */
    uint8_t sa[16];
    pm_memset(sa, 0, 16);
    *(uint16_t*)(sa) = AF_INET;
    *(uint16_t*)(sa+2) = __builtin_bswap16(port);
    *(uint32_t*)(sa+4) = ip;
    return (int)sys6(SYS_SENDTO, fd, (long)buf, len, 0, (long)sa, 16);
}

int relay_register(uint32_t rdv_ip, uint16_t rdv_port, const char *device_id) {
    int fd = (int)sys3(SYS_SOCKET, AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    /* Build RegisterPeer submessage */
    uint8_t sub[256];
    int sn = 0;
    sn += pb_string(sub + sn, 1, device_id, pm_strlen(device_id)); /* field 1: id */
    sn += pb_string(sub + sn, 5, "linux", 5);                      /* field 5: platform */

    /* Wrap in RendezvousMessage envelope (field 6) */
    uint8_t env[512];
    int en = pb_string(env, RDV_REGISTER_PEER, sub, sn);

    udp_sendto(fd, env, en, rdv_ip, rdv_port);
    io_close(fd);
    return 0;
}

int relay_resolve(uint32_t rdv_ip, uint16_t rdv_port, const char *device_id,
                  uint32_t *out_ip, uint16_t *out_port) {
    int fd = (int)sys3(SYS_SOCKET, AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    /* Build PunchHoleRequest submessage */
    uint8_t sub[256];
    int sn = pb_string(sub, 1, device_id, pm_strlen(device_id));

    /* Wrap in envelope (field 8) */
    uint8_t env[512];
    int en = pb_string(env, RDV_PUNCH_HOLE_REQUEST, sub, sn);

    udp_sendto(fd, env, en, rdv_ip, rdv_port);

    /* Receive response (with short timeout) */
    struct { int fd; short events, revents; } pfd = { fd, POLLIN, 0 };
    long pr = sys3(SYS_POLL, (long)&pfd, 1, 3000);
    if (pr <= 0) { io_close(fd); return -1; }

    int r = (int)sys6(SYS_RECVFROM, fd, (long)rdv_buf, 4096, 0, 0, 0);
    io_close(fd);
    if (r <= 0) return -1;

    /* TODO: parse PunchHoleResponse protobuf for socket_addr */
    /* For now, return success if we got a response */
    if (out_ip) *out_ip = 0;
    if (out_port) *out_port = 0;
    return 0;
}
