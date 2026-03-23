/* client.c — Client command dispatch */
#include "sys.h"

static int cli_fd;

static void print_response(void) {
    int ml = proto_recv_msg(cli_fd);
    if (ml <= 0) return;
    if (proto_buf[0] == CMD_EXEC_RESULT && ml > 9)
        io_write(1, proto_buf + 9, ml - 9);
    else if (ml > 1)
        io_write(1, proto_buf + 1, ml - 1);
}

static void send_exec(int fd, const char *cmd) {
    int al = pm_strlen(cmd);
    char buf[65536];
    buf[0] = al >> 8; buf[1] = al & 0xFF;
    pm_memcpy(buf + 2, cmd, al);
    buf[2 + al] = 0;
    proto_send_msg(fd, CMD_EXEC, buf, 3 + al);
}

static void send_fileop(int fd, uint8_t sub, const char *path) {
    int al = pm_strlen(path);
    char buf[512]; buf[0] = sub;
    buf[1] = al >> 8; buf[2] = al & 0xFF;
    pm_memcpy(buf + 3, path, al);
    proto_send_msg(fd, CMD_FILEOPS, buf, 3 + al);
}

void client_run(uint32_t ip, uint16_t port, const char *cmd, const char *arg) {
    auth_load_or_gen();
    int fd = net_socket();
    if (fd < 0) { io_print(2, "Error: connection failed\n"); io_exit(1); }
    cli_fd = fd;
    if (net_connect(fd, ip, port) != 0) { io_print(2, "Error: connection failed\n"); io_exit(1); }
    if (auth_client_handshake(fd) != 0) { io_print(2, "Error: auth failed\n"); io_exit(1); }

    /* --- Command dispatch --- */

    if (!pm_strcmp(cmd, "ping")) {
        proto_send_msg(fd, CMD_PING, 0, 0);
        proto_recv_msg(fd);
        io_print(1, "pong\n");

    } else if (!pm_strcmp(cmd, "exec")) {
        if (!arg) { io_print(2, "Error: missing argument\n"); io_exit(1); }
        send_exec(fd, arg);
        print_response();

    } else if (!pm_strcmp(cmd, "info") || !pm_strcmp(cmd, "version")) {
        proto_send_msg(fd, CMD_INFO_REQ, 0, 0);
        print_response();
        io_print(1, "\n");

    } else if (!pm_strcmp(cmd, "ps")) {
        char sub = 0x01;
        proto_send_msg(fd, CMD_NATIVE, &sub, 1);
        print_response();

    } else if (!pm_strcmp(cmd, "kill")) {
        if (!arg) { io_print(2, "Error: missing argument\n"); io_exit(1); }
        char buf[5]; buf[0] = 0x02;
        *(int*)(buf+1) = __builtin_bswap32(pm_atoi(arg));
        proto_send_msg(fd, CMD_NATIVE, buf, 5);
        print_response();
        io_print(1, "\n");

    } else if (!pm_strcmp(cmd, "push")) {
        if (!arg) { io_print(2, "Error: missing argument\n"); io_exit(1); }
        int ffd = io_open(arg, 0);
        if (ffd < 0) { io_print(2, "Error: file not found\n"); io_exit(1); }
        long fsize = io_filesize(ffd);
        int al = pm_strlen(arg);
        char hdr[512];
        *(long*)hdr = fsize;
        hdr[8] = al >> 8; hdr[9] = al & 0xFF;
        pm_memcpy(hdr + 10, arg, al);
        proto_send_msg(fd, CMD_PUSH_START, hdr, 10 + al);
        for (;;) {
            int r = io_read(ffd, srv_filebuf, 32768);
            if (r <= 0) break;
            proto_send_msg(fd, CMD_PUSH_DATA, srv_filebuf, r);
        }
        io_close(ffd);
        proto_send_msg(fd, CMD_PUSH_END, 0, 0);
        proto_recv_msg(fd);
        io_print(1, "push complete\n");

    } else if (!pm_strcmp(cmd, "pull")) {
        if (!arg) { io_print(2, "Error: missing argument\n"); io_exit(1); }
        int al = pm_strlen(arg);
        char buf[512]; buf[0] = al >> 8; buf[1] = al & 0xFF;
        pm_memcpy(buf + 2, arg, al);
        proto_send_msg(fd, CMD_PULL_REQ, buf, 2 + al);
        int ffd = io_open(arg, 1);
        if (ffd < 0) { io_print(2, "Error: cannot create file\n"); io_exit(1); }
        for (;;) {
            int ml = proto_recv_msg(fd);
            if (ml <= 0) break;
            if (proto_buf[0] == CMD_PULL_DATA) io_write(ffd, proto_buf + 1, ml - 1);
            else if (proto_buf[0] == CMD_PULL_END) break;
        }
        io_close(ffd);
        io_print(1, "pull complete\n");

    } else if (!pm_strcmp(cmd, "write")) {
        if (!arg) { io_print(2, "Error: missing argument\n"); io_exit(1); }
        int sep = -1;
        for (int i = 0; arg[i]; i++) if (arg[i] == ':') { sep = i; break; }
        if (sep < 0) { io_print(2, "Error: format path:content\n"); io_exit(1); }
        char buf[65536];
        buf[0] = sep >> 8; buf[1] = sep & 0xFF;
        pm_memcpy(buf + 2, arg, sep);
        int clen = pm_strlen(arg + sep + 1);
        *(int*)(buf + 2 + sep) = __builtin_bswap32(clen);
        pm_memcpy(buf + 6 + sep, arg + sep + 1, clen);
        proto_send_msg(fd, CMD_WRITE, buf, 6 + sep + clen);
        proto_recv_msg(fd);
        io_print(1, "write complete\n");

    } else if (!pm_strcmp(cmd, "shell")) {
        if (!arg) { io_print(2, "Error: missing argument\n"); io_exit(1); }
        proto_send_msg(fd, CMD_SHELL_REQ, 0, 0);
        proto_send_msg(fd, CMD_SHELL_DATA, arg, pm_strlen(arg));
        int ml = proto_recv_msg(fd);
        if (ml > 1) io_write(1, proto_buf + 1, ml - 1);

    } else if (!pm_strcmp(cmd, "sync")) {
        if (!arg) { io_print(2, "Error: missing argument\n"); io_exit(1); }
        int lfd = io_open(arg, 0);
        int sc = 0;
        if (lfd >= 0) { sc = sync_compute_sigs(lfd); io_seek(lfd, 0, SEEK_SET); }
        int al = pm_strlen(arg);
        char buf[65540];
        buf[0] = al >> 8; buf[1] = al & 0xFF;
        pm_memcpy(buf + 2, arg, al);
        *(uint32_t*)(buf + 2 + al) = __builtin_bswap32(sc);
        pm_memcpy(buf + 6 + al, sync_sigbuf, sc * 8);
        proto_send_msg(fd, CMD_SYNC_REQ, buf, 6 + al + sc * 8);
        int ofd = io_open("/tmp/.pmash_sync.tmp", 1);
        if (ofd >= 0) {
            int r = sync_apply_delta(fd, lfd >= 0 ? lfd : -1, ofd);
            io_close(ofd);
            if (lfd >= 0) io_close(lfd);
            if (r == 0) { sys2(SYS_RENAME, (long)"/tmp/.pmash_sync.tmp", (long)arg); io_print(1, "sync complete\n"); }
            else { sys1(SYS_UNLINK, (long)"/tmp/.pmash_sync.tmp"); io_print(2, "Error: sync failed\n"); }
        } else { if (lfd >= 0) io_close(lfd); io_print(2, "Error: temp file\n"); }

    } else if (!pm_strcmp(cmd, "sync-push")) {
        if (!arg) { io_print(2, "Error: missing argument\n"); io_exit(1); }
        int al = pm_strlen(arg);
        char buf[512]; buf[0] = al >> 8; buf[1] = al & 0xFF;
        pm_memcpy(buf + 2, arg, al);
        proto_send_msg(fd, CMD_SYNC_PUSH_REQ, buf, 2 + al);
        int ml = proto_recv_msg(fd);
        if (ml <= 0 || proto_buf[0] != (char)CMD_SYNC_PUSH_SIGS) { io_print(2, "Error: sync-push\n"); io_exit(1); }
        int sc = __builtin_bswap32(*(uint32_t*)(proto_buf + 1));
        pm_memcpy(sync_sigbuf, proto_buf + 5, sc * 8);
        int lfd = io_open(arg, 0);
        if (lfd < 0) { io_print(2, "Error: file not found\n"); io_exit(1); }
        sync_send_delta(fd, lfd, sync_sigbuf, sc);
        io_close(lfd);
        proto_recv_msg(fd);
        io_print(1, "sync-push complete\n");

    } else if (!pm_strcmp(cmd, "mkdir")) {
        if (!arg) { io_print(2, "Error: missing argument\n"); io_exit(1); }
        send_fileop(fd, 0x01, arg); print_response(); io_print(1, "\n");

    } else if (!pm_strcmp(cmd, "rm")) {
        if (!arg) { io_print(2, "Error: missing argument\n"); io_exit(1); }
        send_fileop(fd, 0x02, arg); print_response(); io_print(1, "\n");

    } else if (!pm_strcmp(cmd, "cat")) {
        if (!arg) { io_print(2, "Error: missing argument\n"); io_exit(1); }
        send_fileop(fd, 0x04, arg); print_response();

    } else if (!pm_strcmp(cmd, "stat")) {
        if (!arg) { io_print(2, "Error: missing argument\n"); io_exit(1); }
        send_fileop(fd, 0x06, arg); print_response(); io_print(1, "\n");

    } else if (!pm_strcmp(cmd, "ls")) {
        char lscmd[512] = "ls ";
        if (arg) { pm_memcpy(lscmd + 3, arg, pm_strlen(arg) + 1); }
        else lscmd[2] = 0;
        send_exec(fd, arg ? lscmd : "ls");
        print_response();

    } else if (!pm_strcmp(cmd, "forward")) {
        /* Port forward -L: forward <local_port>:<remote_host>:<remote_port> */
        if (!arg) { io_print(2, "Error: format local_port:host:port\n"); io_exit(1); }
        /* Parse local_port:remote_ip:remote_port */
        int lport = pm_atoi(arg);
        /* Find first ':' */
        const char *p = arg;
        while (*p && *p != ':') p++;
        if (!*p) { io_print(2, "Error: format local_port:host:port\n"); io_exit(1); }
        p++;
        /* Parse remote host */
        char rhost[64]; int ri = 0;
        while (*p && *p != ':') rhost[ri++] = *p++;
        rhost[ri] = 0;
        if (!*p) { io_print(2, "Error: format local_port:host:port\n"); io_exit(1); }
        p++;
        int rport = pm_atoi(p);
        uint32_t rip = parse_ip(rhost);

        /* Listen locally */
        int lfd = net_socket();
        if (lfd < 0) { io_print(2, "Error: socket\n"); io_exit(1); }
        if (net_bind(lfd, lport) != 0) { io_print(2, "Error: bind\n"); io_exit(1); }
        net_listen(lfd, 5);
        io_print(1, "Forwarding...\n");

        /* Accept one connection, tunnel through pmash server */
        int afd = net_accept(lfd);
        if (afd < 0) { io_print(2, "Error: accept\n"); io_exit(1); }

        /* Send TUNNEL_OPEN to pmash server */
        char tbuf[6];
        *(uint32_t*)tbuf = rip;
        tbuf[4] = rport >> 8; tbuf[5] = rport & 0xFF;
        proto_send_msg(fd, CMD_TUNNEL_OPEN, tbuf, 6);
        int ml = proto_recv_msg(fd);
        if (ml <= 0 || proto_buf[0] != (char)CMD_TUNNEL_OK) {
            io_print(2, "Error: tunnel failed\n");
            io_close(afd); io_close(lfd); io_exit(1);
        }
        /* Bidirectional: local_client ↔ pmash_server (raw) */
        proxy_forward(afd, fd);
        io_close(afd); io_close(lfd);

    } else if (!pm_strcmp(cmd, "socks")) {
        /* SOCKS5 proxy -D: socks <local_port> */
        if (!arg) { io_print(2, "Error: socks <port>\n"); io_exit(1); }
        int lport = pm_atoi(arg);
        int lfd = net_socket();
        if (lfd < 0 || net_bind(lfd, lport) != 0 || net_listen(lfd, 5) != 0) {
            io_print(2, "Error: bind\n"); io_exit(1);
        }
        io_print(1, "SOCKS5 listening...\n");

        for (;;) {
            int afd = net_accept(lfd);
            if (afd < 0) continue;
            /* SOCKS5 greeting */
            char gbuf[512];
            int gr = io_read(afd, gbuf, 512);
            if (gr < 2 || gbuf[0] != 0x05) { io_close(afd); continue; }
            /* Reply: no auth */
            char rep[2] = { 0x05, 0x00 };
            io_write(afd, rep, 2);
            /* SOCKS5 request */
            gr = io_read(afd, gbuf, 512);
            if (gr < 4 || gbuf[1] != 0x01) { /* only CONNECT */
                char fail[10] = { 0x05, 0x07, 0,1, 0,0,0,0, 0,0 };
                io_write(afd, fail, 10); io_close(afd); continue;
            }
            uint32_t dst_ip = 0; uint16_t dst_port = 0;
            if (gbuf[3] == 0x01) { /* IPv4 */
                dst_ip = *(uint32_t*)(gbuf + 4);
                dst_port = (gbuf[8] << 8) | gbuf[9];
            } else { /* domain/ipv6 not supported */
                char fail[10] = { 0x05, 0x08, 0,1, 0,0,0,0, 0,0 };
                io_write(afd, fail, 10); io_close(afd); continue;
            }
            /* Tunnel through pmash server */
            char tbuf[6];
            *(uint32_t*)tbuf = dst_ip;
            tbuf[4] = dst_port >> 8; tbuf[5] = dst_port & 0xFF;
            proto_send_msg(fd, CMD_TUNNEL_OPEN, tbuf, 6);
            int ml = proto_recv_msg(fd);
            if (ml <= 0 || proto_buf[0] != (char)CMD_TUNNEL_OK) {
                char fail[10] = { 0x05, 0x05, 0,1, 0,0,0,0, 0,0 };
                io_write(afd, fail, 10); io_close(afd); continue;
            }
            /* SOCKS5 success */
            char ok[10] = { 0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0 };
            io_write(afd, ok, 10);
            /* Forward */
            proxy_forward(afd, fd);
            io_close(afd);
            break; /* one connection per pmash session */
        }
        io_close(lfd);

    } else {
        /* Default: exec the command name */
        send_exec(fd, cmd);
        print_response();
    }

    io_close(fd);
    io_exit(0);
}
