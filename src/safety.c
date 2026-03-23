/* safety.c — Safety guards + rate limiting */
#include "sys.h"

static int contains(const char *hay, const char *needle) {
    int nlen = pm_strlen(needle);
    for (int i = 0; hay[i]; i++)
        if (pm_memcmp(hay + i, needle, nlen) == 0) return 1;
    return 0;
}

int safety_check(const char *cmd) {
    if (!contains(cmd, "pmash")) return 0;
    if (contains(cmd, "systemctl stop pmash")) return 1;
    if (contains(cmd, "service pmash stop")) return 1;
    if (contains(cmd, "killall pmash")) return 1;
    if (contains(cmd, "pkill pmash")) return 1;
    if (contains(cmd, "rm /usr/local/bin/pmash")) return 1;
    return 0;
}

static int rl_fail_count = 0, rl_banned = 0;

void rl_check(void) {
    if (rl_banned) { io_sleep_ms(300000); rl_banned = 0; rl_fail_count = 0; }
}
void rl_fail(void) { if (++rl_fail_count >= 5) rl_banned = 1; }
void rl_success(void) { rl_fail_count = 0; rl_banned = 0; }
