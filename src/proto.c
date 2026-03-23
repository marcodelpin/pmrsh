/* proto.c — Wire protocol: [4-byte BE length][cmdId][payload] */
#include "sys.h"

char proto_buf[65536];
char proto_hdr[4];

int proto_send_all(int fd, const void *buf, int len) {
    const char *p = buf;
    while (len > 0) {
        ssize_t r = io_write(fd, p, len);
        if (r <= 0) return -1;
        p += r; len -= r;
    }
    return 0;
}

int proto_recv_all(int fd, void *buf, int len) {
    char *p = buf; int total = 0;
    while (len > 0) {
        ssize_t r = io_read(fd, p, len);
        if (r <= 0) return total;
        p += r; total += r; len -= r;
    }
    return total;
}

int proto_send_msg(int fd, uint8_t cmd, const void *payload, int plen) {
    int total = 1 + plen;
    uint32_t hdr = __builtin_bswap32(total);
    if (proto_send_all(fd, &hdr, 4) < 0) return -1;
    proto_buf[0] = cmd;
    if (plen > 0) pm_memcpy(proto_buf + 1, payload, plen);
    return proto_send_all(fd, proto_buf, total);
}

int proto_recv_msg(int fd) {
    if (proto_recv_all(fd, proto_hdr, 4) != 4) return -1;
    uint32_t len = __builtin_bswap32(*(uint32_t*)proto_hdr);
    if (len == 0 || len > 65536) return -1;
    return proto_recv_all(fd, proto_buf, len);
}
