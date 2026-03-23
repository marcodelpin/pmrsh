/* sync.c — Delta sync: Adler32 block sigs + M/D/E transfer */
#include "sys.h"

uint8_t sync_blockbuf[SYNC_BLOCK_SIZE];
uint8_t sync_sigbuf[65536];

uint32_t adler32(const uint8_t *data, size_t len) {
    uint32_t a = 1, b = 0;
    for (size_t i = 0; i < len; i++) {
        a = (a + data[i]) % 65521;
        b = (b + a) % 65521;
    }
    return (b << 16) | a;
}

int sync_compute_sigs(int fd) {
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

void sync_send_delta(int net_fd, int file_fd, const uint8_t *sigs, int sig_count) {
    for (;;) {
        int r = io_read(file_fd, sync_blockbuf, SYNC_BLOCK_SIZE);
        if (r <= 0) break;
        uint32_t hash = adler32(sync_blockbuf, r);
        int matched = -1;
        for (int i = 0; i < sig_count; i++) {
            uint32_t *sig = (uint32_t*)(sigs + i * 8);
            if (sig[1] == hash) { matched = sig[0]; break; }
        }
        if (matched >= 0) {
            char m[5] = { DELTA_MATCH };
            *(uint32_t*)(m+1) = __builtin_bswap32(matched);
            proto_send_msg(net_fd, CMD_SYNC_RESP, m, 5);
        } else {
            char d[5 + SYNC_BLOCK_SIZE];
            d[0] = DELTA_DATA;
            *(uint32_t*)(d+1) = __builtin_bswap32(r);
            pm_memcpy(d + 5, sync_blockbuf, r);
            proto_send_msg(net_fd, CMD_SYNC_RESP, d, 5 + r);
        }
    }
    char e = DELTA_END;
    proto_send_msg(net_fd, CMD_SYNC_RESP, &e, 1);
}

int sync_apply_delta(int net_fd, int local_fd, int out_fd) {
    for (;;) {
        int ml = proto_recv_msg(net_fd);
        if (ml <= 0) return -1;
        if (proto_buf[0] != (char)CMD_SYNC_RESP) return -1;
        uint8_t marker = proto_buf[1];
        if (marker == DELTA_END) return 0;
        if (marker == DELTA_MATCH && local_fd >= 0) {
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
