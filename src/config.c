/* config.c — SSH-style config file + port auto-try
 *
 * Config at ~/.pmrsh/config:
 *   Host myserver
 *     HostName 192.168.1.10
 *     Port 9822
 *     MAC aa:bb:cc:dd:ee:ff
 */
#include "sys.h"

#define MAX_HOSTS 32

struct host_entry {
    char name[64];
    char hostname[64];
    uint16_t port;
    char mac[18]; /* aa:bb:cc:dd:ee:ff */
};

static struct host_entry hosts[MAX_HOSTS];
static int host_count = 0;
static char config_path[200];
static int config_loaded = 0;

void config_init(const char *home) {
    int hl = pm_strlen(home);
    pm_memcpy(config_path, home, hl);
    pm_memcpy(config_path + hl, "/.pmrsh/config", 15);
}

static void config_load(void) {
    if (config_loaded) return;
    config_loaded = 1;
    int fd = io_open(config_path, 0);
    if (fd < 0) return;
    char buf[4096];
    int n = io_read(fd, buf, sizeof(buf) - 1);
    io_close(fd);
    if (n <= 0) return;
    buf[n] = 0;

    /* Parse line by line */
    int cur = -1;
    char *p = buf;
    while (*p) {
        /* Skip leading whitespace */
        int indent = 0;
        while (*p == ' ' || *p == '\t') { p++; indent++; }
        /* Find end of line */
        char *eol = p;
        while (*eol && *eol != '\n') eol++;

        if (p == eol || *p == '#') { /* empty/comment */
            p = (*eol) ? eol + 1 : eol;
            continue;
        }

        /* Null-terminate this line */
        char saved = *eol; *eol = 0;

        if (indent == 0 && pm_memcmp(p, "Host ", 5) == 0) {
            if (host_count >= MAX_HOSTS) break;
            cur = host_count++;
            pm_memset(&hosts[cur], 0, sizeof(hosts[cur]));
            int nl = pm_strlen(p + 5);
            if (nl > 63) nl = 63;
            pm_memcpy(hosts[cur].name, p + 5, nl);
            hosts[cur].port = 8822;
        } else if (cur >= 0) {
            if (pm_memcmp(p, "HostName ", 9) == 0) {
                int nl = pm_strlen(p + 9); if (nl > 63) nl = 63;
                pm_memcpy(hosts[cur].hostname, p + 9, nl);
            } else if (pm_memcmp(p, "Port ", 5) == 0) {
                hosts[cur].port = pm_atoi(p + 5);
            } else if (pm_memcmp(p, "MAC ", 4) == 0) {
                int nl = pm_strlen(p + 4); if (nl > 17) nl = 17;
                pm_memcpy(hosts[cur].mac, p + 4, nl);
            }
        }

        *eol = saved;
        p = (*eol) ? eol + 1 : eol;
    }
}

/* Lookup host by name → fill ip + port. Returns 0 on match. */
int config_lookup(const char *name, uint32_t *ip, uint16_t *port, char *mac) {
    config_load();
    for (int i = 0; i < host_count; i++) {
        if (!pm_strcmp(hosts[i].name, name)) {
            if (ip && hosts[i].hostname[0]) *ip = parse_ip(hosts[i].hostname);
            if (port) *port = hosts[i].port;
            if (mac && hosts[i].mac[0]) pm_memcpy(mac, hosts[i].mac, 18);
            return 0;
        }
    }
    return -1;
}

/* Port auto-try: try 8822 → 9822 → 22 */
int net_connect_auto(int fd, uint32_t ip, uint16_t port) {
    /* If explicit port given, use it */
    if (port != 8822) return net_connect(fd, ip, port);
    /* Auto-try */
    uint16_t ports[] = { 8822, 9822, 22 };
    for (int i = 0; i < 3; i++) {
        /* Need a new socket for each attempt (connect failure taints fd) */
        if (i > 0) {
            io_close(fd);
            fd = net_socket();
            if (fd < 0) return -1;
        }
        if (net_connect(fd, ip, ports[i]) == 0) return fd;
    }
    return -1; /* all failed */
}
