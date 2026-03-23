/* system.c — System commands: reboot, shutdown, WoL, service mgmt, screenshot */
#include "sys.h"

#define CMD_SYSTEM      0xC0
#define CMD_SYSTEM_RESP 0xC1

/* Sub-commands */
#define SYS_CMD_REBOOT    0x01
#define SYS_CMD_SHUTDOWN  0x02
#define SYS_CMD_SLEEP     0x03
#define SYS_CMD_WOL       0x04
#define SYS_CMD_SVC_LIST  0x10
#define SYS_CMD_SVC_START 0x11
#define SYS_CMD_SVC_STOP  0x12
#define SYS_CMD_SVC_STATUS 0x13
#define SYS_CMD_SCREENSHOT 0x20

/* Server handler */
void system_handle(int cfd) {
    uint8_t sub = proto_buf[1];
    int n;

    switch (sub) {
    case SYS_CMD_REBOOT:
        proto_send_msg(cfd, CMD_SYSTEM_RESP, "rebooting", 9);
        io_exec("reboot", srv_execbuf, 256);
        break;

    case SYS_CMD_SHUTDOWN:
        proto_send_msg(cfd, CMD_SYSTEM_RESP, "shutting down", 13);
        io_exec("shutdown -h now", srv_execbuf, 256);
        break;

    case SYS_CMD_SLEEP:
        proto_send_msg(cfd, CMD_SYSTEM_RESP, "suspending", 10);
        io_exec("systemctl suspend", srv_execbuf, 256);
        break;

    case SYS_CMD_WOL: {
        /* Payload: 6 bytes MAC + optional IP */
        if (proto_buf[2] == 0) break; /* no MAC */
        /* Build etherwake/wakeonlan command */
        char wol[80] = "wakeonlan ";
        char *p = wol + 10;
        for (int i = 0; i < 6; i++) {
            uint8_t b = proto_buf[2 + i];
            *p++ = "0123456789abcdef"[b >> 4];
            *p++ = "0123456789abcdef"[b & 0xF];
            if (i < 5) *p++ = ':';
        }
        *p = 0;
        n = io_exec(wol, srv_execbuf, 512);
        proto_send_msg(cfd, CMD_SYSTEM_RESP, n >= 0 ? "wol sent" : "wol failed",
                       n >= 0 ? 8 : 10);
        break;
    }

    case SYS_CMD_SVC_LIST:
        n = io_exec("systemctl list-units --type=service --no-pager --no-legend 2>/dev/null | head -50",
                     srv_execbuf, 65536);
        if (n > 0) proto_send_msg(cfd, CMD_SYSTEM_RESP, srv_execbuf, n);
        else proto_send_msg(cfd, CMD_SYSTEM_RESP, "error", 5);
        break;

    case SYS_CMD_SVC_START:
    case SYS_CMD_SVC_STOP:
    case SYS_CMD_SVC_STATUS: {
        char *svc = proto_buf + 2;
        int sl = pm_strlen(svc);
        if (sl == 0 || sl > 64) { proto_send_msg(cfd, CMD_SYSTEM_RESP, "error", 5); break; }
        char cmd[128];
        const char *action = (sub == SYS_CMD_SVC_START) ? "start" :
                             (sub == SYS_CMD_SVC_STOP) ? "stop" : "status";
        int al = pm_strlen(action);
        pm_memcpy(cmd, "systemctl ", 10);
        pm_memcpy(cmd + 10, action, al);
        cmd[10 + al] = ' ';
        pm_memcpy(cmd + 11 + al, svc, sl + 1);
        n = io_exec(cmd, srv_execbuf, 4096);
        if (n > 0) proto_send_msg(cfd, CMD_SYSTEM_RESP, srv_execbuf, n);
        else proto_send_msg(cfd, CMD_SYSTEM_RESP, "error", 5);
        break;
    }

    case SYS_CMD_SCREENSHOT:
        /* Headless screenshot via fbdev → raw framebuffer dump */
        n = io_exec("cat /dev/fb0 2>/dev/null | head -c 1000000",
                     srv_execbuf, 65536);
        if (n > 0) proto_send_msg(cfd, CMD_SYSTEM_RESP, srv_execbuf, n);
        else proto_send_msg(cfd, CMD_SYSTEM_RESP, "no framebuffer", 14);
        break;

    default:
        proto_send_msg(cfd, CMD_SYSTEM_RESP, "unknown", 7);
    }
}

/* WoL: send magic packet from client (no server needed) */
int wol_send(const char *mac_str) {
    /* Parse MAC: "aa:bb:cc:dd:ee:ff" → 6 bytes */
    uint8_t mac[6];
    const char *p = mac_str;
    for (int i = 0; i < 6; i++) {
        int hi = (*p >= 'a') ? *p - 'a' + 10 : (*p >= 'A') ? *p - 'A' + 10 : *p - '0'; p++;
        int lo = (*p >= 'a') ? *p - 'a' + 10 : (*p >= 'A') ? *p - 'A' + 10 : *p - '0'; p++;
        mac[i] = (hi << 4) | lo;
        if (*p == ':') p++;
    }

    /* Build magic packet: 6x 0xFF + 16x MAC */
    uint8_t pkt[102];
    pm_memset(pkt, 0xFF, 6);
    for (int i = 0; i < 16; i++) pm_memcpy(pkt + 6 + i * 6, mac, 6);

    /* Send via UDP broadcast */
    int fd = (int)sys3(SYS_SOCKET, AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    int one = 1;
    sys5(SYS_SETSOCKOPT, fd, SOL_SOCKET, 6/*SO_BROADCAST*/, (long)&one, 4);
    struct sockaddr_in sa = { AF_INET, __builtin_bswap16(9), 0xFFFFFFFF, 0 };
    sys6(SYS_SENDTO, fd, (long)pkt, 102, 0, (long)&sa, sizeof(sa));
    io_close(fd);
    return 0;
}

/* Parse MAC from config for WoL */
int wol_by_name(const char *name) {
    char mac[18] = {0};
    uint32_t ip; uint16_t port;
    if (config_lookup(name, &ip, &port, mac) == 0 && mac[0]) {
        return wol_send(mac);
    }
    return -1;
}
