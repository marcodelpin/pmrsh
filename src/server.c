/* server.c — Server loop + command dispatch */
#include "sys.h"

char srv_execbuf[65536];
char srv_filebuf[32768];
char srv_infobuf[512];
char srv_hostbuf[256];
int  srv_client;

static void srv_send_error(int fd) {
    char err[17] = { 0, 15 };
    pm_memcpy(err + 2, "unknown command", 15);
    proto_send_msg(fd, CMD_ERROR, err, 17);
}

static void srv_do_exec(int cfd, int mlen) {
    int slen = (proto_buf[1] << 8) | proto_buf[2];
    char *cmd = proto_buf + 3;
    cmd[slen] = 0;

    if (safety_check(cmd)) {
        const char *blocked = "BLOCKED: self-destructive command";
        int blen = pm_strlen(blocked);
        char r[512]; *(int*)r = 1;
        *(int*)(r+4) = __builtin_bswap32(blen);
        pm_memcpy(r + 8, blocked, blen);
        proto_send_msg(cfd, CMD_EXEC_RESULT, r, 8 + blen);
        return;
    }

    int olen = io_exec(cmd, srv_execbuf, 65536);
    if (olen < 0) { srv_send_error(cfd); return; }
    char r[65544]; *(int*)r = 0;
    *(int*)(r+4) = __builtin_bswap32(olen);
    pm_memcpy(r + 8, srv_execbuf, olen);
    proto_send_msg(cfd, CMD_EXEC_RESULT, r, 8 + olen);
}

static void srv_do_info(int cfd) {
    io_hostname(srv_hostbuf, 255);
    int n = 0;
    const char *p1 = "{\"hostname\":\"";
    int p1l = pm_strlen(p1);
    pm_memcpy(srv_infobuf, p1, p1l); n = p1l;
    int hl = pm_strlen(srv_hostbuf);
    pm_memcpy(srv_infobuf + n, srv_hostbuf, hl); n += hl;
    const char *p2 = "\",\"version\":\"pmash 0.2.0\",\"os\":\"Linux\"}";
    int p2l = pm_strlen(p2);
    pm_memcpy(srv_infobuf + n, p2, p2l); n += p2l;
    proto_send_msg(cfd, CMD_INFO_RESP, srv_infobuf, n);
}

static void srv_do_push(int cfd) {
    char *p = proto_buf + 1 + 8;
    int plen = (p[0] << 8) | p[1]; p += 2;
    p[plen] = 0;
    int ffd = io_open(p, 1);
    if (ffd < 0) { srv_send_error(cfd); return; }
    for (;;) {
        int ml = proto_recv_msg(cfd);
        if (ml <= 0) break;
        if (proto_buf[0] == CMD_PUSH_DATA) io_write(ffd, proto_buf + 1, ml - 1);
        else if (proto_buf[0] == CMD_PUSH_END) break;
    }
    io_close(ffd);
    proto_send_msg(cfd, CMD_PUSH_OK, 0, 0);
}

static void srv_do_pull(int cfd) {
    char *p = proto_buf + 1;
    int plen = (p[0] << 8) | p[1]; p += 2;
    p[plen] = 0;
    int ffd = io_open(p, 0);
    if (ffd < 0) { srv_send_error(cfd); return; }
    for (;;) {
        int r = io_read(ffd, srv_filebuf, 32768);
        if (r <= 0) break;
        proto_send_msg(cfd, CMD_PULL_DATA, srv_filebuf, r);
    }
    io_close(ffd);
    proto_send_msg(cfd, CMD_PULL_END, 0, 0);
}

static void srv_do_write(int cfd) {
    char *p = proto_buf + 1;
    int plen = (p[0] << 8) | p[1]; p += 2;
    p[plen] = 0; char *path = p; p += plen;
    int clen = __builtin_bswap32(*(int*)p); p += 4;
    int ffd = io_open(path, 1);
    if (ffd >= 0) { io_write(ffd, p, clen); io_close(ffd); }
    proto_send_msg(cfd, ffd >= 0 ? CMD_WRITE_OK : CMD_ERROR, 0, 0);
}

static void srv_do_native(int cfd) {
    uint8_t sub = proto_buf[1];
    if (sub == 0x01) {
        int n = io_exec("ps -eo pid,comm --no-headers", srv_execbuf, 65536);
        if (n > 0) proto_send_msg(cfd, CMD_NATIVE_RESP, srv_execbuf, n);
        else srv_send_error(cfd);
    } else if (sub == 0x02) {
        int pid = __builtin_bswap32(*(int*)(proto_buf + 2));
        char kc[32] = "kill -9 ";
        char tmp[12]; int ti = 11; tmp[11] = 0;
        int p = pid; if (p == 0) tmp[--ti] = '0';
        while (p > 0) { tmp[--ti] = '0' + (p % 10); p /= 10; }
        pm_memcpy(kc + 8, tmp + ti, 11 - ti + 1);
        int n = io_exec(kc, srv_execbuf, 512);
        const char *res = (n >= 0) ? "killed" : "kill failed";
        proto_send_msg(cfd, CMD_NATIVE_RESP, res, pm_strlen(res));
    } else srv_send_error(cfd);
}

static void srv_do_shell(int cfd) {
    for (;;) {
        int ml = proto_recv_msg(cfd);
        if (ml <= 0 || (uint8_t)proto_buf[0] != CMD_SHELL_DATA) break;
        proto_buf[ml] = 0;
        int n = io_exec(proto_buf + 1, srv_execbuf, 65536);
        if (n > 0) proto_send_msg(cfd, CMD_SHELL_DATA, srv_execbuf, n);
    }
}

static void srv_do_sync(int cfd) {
    char *p = proto_buf + 1;
    int plen = (p[0] << 8) | p[1]; p += 2;
    p[plen] = 0; char *path = p; p += plen;
    int sc = __builtin_bswap32(*(uint32_t*)p); p += 4;
    int ffd = io_open(path, 0);
    if (ffd >= 0) {
        sync_send_delta(cfd, ffd, (uint8_t*)p, sc);
        io_close(ffd);
    } else srv_send_error(cfd);
}

static void srv_do_sync_push(int cfd) {
    char *p = proto_buf + 1;
    int plen = (p[0] << 8) | p[1]; p += 2;
    p[plen] = 0; char *path = p;
    int local_fd = io_open(path, 0);
    int sc = 0;
    if (local_fd >= 0) { sc = sync_compute_sigs(local_fd); io_seek(local_fd, 0, SEEK_SET); }
    char sbuf[65540];
    *(uint32_t*)sbuf = __builtin_bswap32(sc);
    pm_memcpy(sbuf + 4, sync_sigbuf, sc * 8);
    proto_send_msg(cfd, CMD_SYNC_PUSH_SIGS, sbuf, 4 + sc * 8);
    int ofd = io_open("/tmp/.pmash_sync.tmp", 1);
    if (ofd >= 0) {
        int r = sync_apply_delta(cfd, local_fd >= 0 ? local_fd : -1, ofd);
        io_close(ofd);
        if (local_fd >= 0) io_close(local_fd);
        if (r == 0) {
            sys2(SYS_RENAME, (long)"/tmp/.pmash_sync.tmp", (long)path);
            proto_send_msg(cfd, CMD_SYNC_PUSH_OK, 0, 0);
        } else {
            sys1(SYS_UNLINK, (long)"/tmp/.pmash_sync.tmp");
            srv_send_error(cfd);
        }
    } else { if (local_fd >= 0) io_close(local_fd); srv_send_error(cfd); }
}

static void srv_do_fileops(int cfd) {
    uint8_t sub = proto_buf[1];
    char *p = proto_buf + 2;
    int plen = (p[0] << 8) | p[1]; p += 2;
    p[plen] = 0;
    if (sub == 0x01) { sys2(SYS_MKDIR, (long)p, 0755); proto_send_msg(cfd, CMD_FILEOPS_RESP, "ok", 2); }
    else if (sub == 0x02) { sys1(SYS_UNLINK, (long)p); proto_send_msg(cfd, CMD_FILEOPS_RESP, "ok", 2); }
    else if (sub == 0x04) {
        int ffd = io_open(p, 0);
        if (ffd >= 0) {
            int n = io_read(ffd, srv_filebuf, 65536); io_close(ffd);
            proto_send_msg(cfd, CMD_FILEOPS_RESP, n > 0 ? srv_filebuf : "error", n > 0 ? n : 5);
        } else proto_send_msg(cfd, CMD_FILEOPS_RESP, "error", 5);
    } else if (sub == 0x06) {
        int ffd = io_open(p, 0);
        if (ffd >= 0) {
            long sz = io_filesize(ffd); io_close(ffd);
            proto_send_msg(cfd, CMD_FILEOPS_RESP, &sz, 8);
        } else proto_send_msg(cfd, CMD_FILEOPS_RESP, "error", 5);
    } else srv_send_error(cfd);
}

static void srv_do_selfupdate(int cfd) {
    char cur[512], bak[520];
    int r = sys3(SYS_READLINK, (long)"/proc/self/exe", (long)cur, 511);
    if (r <= 0) return;
    cur[r] = 0;
    pm_memcpy(bak, cur, r);
    pm_memcpy(bak + r, ".bak", 5);
    sys2(SYS_RENAME, (long)cur, (long)bak);
    sys2(SYS_RENAME, (long)(proto_buf + 1), (long)cur);
    proto_send_msg(cfd, CMD_SELF_UPDATE_OK, 0, 0);
    io_exit(0);
}

void server_run(uint16_t port) {
    int lfd = net_socket();
    if (lfd < 0) return;
    if (net_bind(lfd, port) != 0) { io_close(lfd); return; }
    net_listen(lfd, 5);

    for (;;) {
        int cfd = net_accept(lfd);
        if (cfd < 0) continue;
        srv_client = cfd;
        rl_check();

        /* TLS: peek first byte, if 0x16 and cert exists → TLS handshake */
        if (tls_server_should_try(cfd)) {
            tls_server_accept(cfd);
            /* TLS failure → disconnect (don't fall back, client sent TLS) */
        }

        if (auth_server_handshake(cfd) != 0) { rl_fail(); tls_close_session(1); io_close(cfd); continue; }
        rl_success();

        for (;;) {
            int mlen = proto_recv_msg(cfd);
            if (mlen <= 0) break;
            uint8_t cmd = proto_buf[0];

            switch (cmd) {
            case CMD_PING:         proto_send_msg(cfd, CMD_PONG, 0, 0); break;
            case CMD_EXEC:         srv_do_exec(cfd, mlen); break;
            case CMD_INFO_REQ:     srv_do_info(cfd); break;
            case CMD_PUSH_START:   srv_do_push(cfd); break;
            case CMD_PULL_REQ:     srv_do_pull(cfd); break;
            case CMD_WRITE:        srv_do_write(cfd); break;
            case CMD_NATIVE:       srv_do_native(cfd); break;
            case CMD_SHELL_REQ:    srv_do_shell(cfd); break;
            case CMD_SYNC_REQ:     srv_do_sync(cfd); break;
            case CMD_SYNC_PUSH_REQ: srv_do_sync_push(cfd); break;
            case CMD_FILEOPS:      srv_do_fileops(cfd); break;
            case CMD_SELF_UPDATE:  srv_do_selfupdate(cfd); break;
            case CMD_PROXY_CONNECT: {
                char *p = proto_buf + 1;
                int pl = (p[0]<<8)|p[1]; p += 2; p[pl] = 0;
                int tfd = net_socket();
                if (tfd >= 0 && net_connect(tfd, 0x0100007F, 8822) == 0) {
                    proto_send_msg(cfd, CMD_PROXY_OK, 0, 0);
                    proxy_forward(cfd, tfd); io_close(tfd);
                } else { if (tfd >= 0) io_close(tfd); srv_send_error(cfd); }
                goto disconnect;
            }
            case CMD_TUNNEL_OPEN:  tunnel_handle(cfd); goto disconnect;
            case 0xC0:             system_handle(cfd); break; /* CMD_SYSTEM */
            case 0x82:             session_handle(cfd); goto disconnect; /* PTY session */
            default:               srv_send_error(cfd); break;
            }
        }
    disconnect:
        tls_close_session(1);
        io_close(cfd);
    }
}
