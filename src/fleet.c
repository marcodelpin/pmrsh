/* fleet.c — Multi-host status probing, known hosts, fingerprint pinning */
#include "sys.h"

/* === Known hosts (TOFU fingerprint pinning) === */

static char known_hosts_path[200];

void known_hosts_init(const char *home) {
    int hl = pm_strlen(home);
    pm_memcpy(known_hosts_path, home, hl);
    pm_memcpy(known_hosts_path + hl, "/.pmash/known_hosts", 20);
}

/* Store fingerprint: "host:port fingerprint\n" */
int known_hosts_pin(const char *host, uint16_t port, const uint8_t *fp, int fplen) {
    int fd = (int)sys3(SYS_OPEN, (long)known_hosts_path,
                       O_WRONLY | O_CREAT | 1024/*O_APPEND*/, 0600);
    if (fd < 0) return -1;
    char line[256];
    int n = 0;
    int hl = pm_strlen(host);
    pm_memcpy(line, host, hl); n += hl;
    line[n++] = ':';
    /* itoa port */
    char tmp[8]; int ti = 7; tmp[7] = 0;
    int p = port; if (p == 0) tmp[--ti] = '0';
    while (p > 0) { tmp[--ti] = '0' + (p % 10); p /= 10; }
    pm_memcpy(line + n, tmp + ti, 7 - ti); n += 7 - ti;
    line[n++] = ' ';
    /* Hex fingerprint */
    for (int i = 0; i < fplen && n < 240; i++) {
        line[n++] = "0123456789abcdef"[fp[i] >> 4];
        line[n++] = "0123456789abcdef"[fp[i] & 0xF];
    }
    line[n++] = '\n';
    io_write(fd, line, n);
    io_close(fd);
    return 0;
}

/* Check if host fingerprint matches stored. Returns 0=match, 1=mismatch, -1=not found */
int known_hosts_check(const char *host, uint16_t port, const uint8_t *fp, int fplen) {
    int fd = io_open(known_hosts_path, 0);
    if (fd < 0) return -1; /* no known_hosts file = first time */
    char buf[4096];
    int n = io_read(fd, buf, sizeof(buf) - 1);
    io_close(fd);
    if (n <= 0) return -1;
    buf[n] = 0;

    /* Build search key "host:port " */
    char key[128];
    int kn = 0;
    int hl = pm_strlen(host);
    pm_memcpy(key, host, hl); kn += hl;
    key[kn++] = ':';
    char tmp[8]; int ti = 7; tmp[7] = 0;
    int p = port; if (p == 0) tmp[--ti] = '0';
    while (p > 0) { tmp[--ti] = '0' + (p % 10); p /= 10; }
    pm_memcpy(key + kn, tmp + ti, 7 - ti); kn += 7 - ti;
    key[kn++] = ' ';
    key[kn] = 0;

    /* Search */
    char *found = buf;
    for (;;) {
        int match = 1;
        for (int i = 0; i < kn; i++) {
            if (found[i] != key[i]) { match = 0; break; }
        }
        if (match) {
            /* Compare hex fingerprint */
            char *fp_str = found + kn;
            for (int i = 0; i < fplen; i++) {
                char hi = "0123456789abcdef"[fp[i] >> 4];
                char lo = "0123456789abcdef"[fp[i] & 0xF];
                if (fp_str[i*2] != hi || fp_str[i*2+1] != lo) return 1; /* mismatch */
            }
            return 0; /* match */
        }
        /* Next line */
        while (*found && *found != '\n') found++;
        if (!*found) break;
        found++;
    }
    return -1; /* not found */
}

/* === Fleet status probe === */

/* Probe a single host: connect + ping + disconnect */
static int probe_one(uint32_t ip, uint16_t port) {
    int fd = net_socket();
    if (fd < 0) return -1;
    /* Quick connect with 2-second timeout via poll */
    /* Non-blocking connect would be better but simpler: just try */
    if (net_connect(fd, ip, port) != 0) { io_close(fd); return -1; }
    if (auth_client_handshake(fd) != 0) { io_close(fd); return -1; }
    proto_send_msg(fd, CMD_PING, 0, 0);
    int ml = proto_recv_msg(fd);
    io_close(fd);
    return (ml > 0 && proto_buf[0] == CMD_PONG) ? 0 : -1;
}

/* Probe all hosts from config, print results */
void fleet_status(void) {
    /* Load config */
    for (int i = 0; ; i++) {
        /* Use config_lookup with index — but we need to iterate.
         * For simplicity, just call probe for known hosts from config.
         * The config parser stores hosts internally — we need an accessor. */
        /* TODO: expose config host list for iteration */
        break;
    }
}
