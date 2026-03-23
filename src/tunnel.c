/* tunnel.c — Proxy forwarding, port forwarding -L, SOCKS5 -D */
#include "sys.h"

void proxy_forward(int fd_a, int fd_b) {
    char buf[16384];
    for (;;) {
        struct { int fd; short events, revents; } pfds[2];
        pfds[0] = (typeof(pfds[0])){ fd_a, POLLIN, 0 };
        pfds[1] = (typeof(pfds[1])){ fd_b, POLLIN, 0 };
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

void tunnel_handle(int client_fd) {
    uint32_t ip = *(uint32_t*)(proto_buf + 1);
    uint16_t port = (proto_buf[5] << 8) | proto_buf[6];
    int tfd = net_socket();
    if (tfd < 0 || net_connect(tfd, ip, port) != 0) {
        proto_send_msg(client_fd, CMD_TUNNEL_FAIL, 0, 0);
        if (tfd >= 0) io_close(tfd);
        return;
    }
    proto_send_msg(client_fd, CMD_TUNNEL_OK, 0, 0);
    proxy_forward(client_fd, tfd);
    io_close(tfd);
}
