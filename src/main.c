/* main.c — Entry point + CLI parsing */
#include "sys.h"

#define VERSION "pmash 0.2.0 (x86_64)\n"
#define USAGE   "Usage: pmash -h <host> [-p <port>] <cmd> [arg]\n" \
                "       pmash --listen <port>\n" \
                "       pmash --daemon <port>\n" \
                "       pmash --version\n" \
                "Commands: ping exec info ps kill push pull write shell\n" \
                "          sync sync-push mkdir rm cat stat ls\n" \
                "          forward <lport:host:rport> socks <port>\n" \
                "          wol <mac|host> reboot shutdown service batch session fleet\n"

static void pmash_run(int argc, char **argv, const char *home) {
    auth_resolve_paths(home);
    tls_init(home);
    config_init(home);
    known_hosts_init(home);

    if (argc < 2) { io_print(2, USAGE); io_exit(1); }

    uint32_t host_ip = 0;
    uint16_t port = 8822;
    const char *cmd = 0, *arg = 0;

    for (int i = 1; i < argc; i++) {
        if (!pm_strcmp(argv[i], "--version")) {
            io_print(1, VERSION); io_exit(0);
        } else if (!pm_strcmp(argv[i], "--listen") && i+1 < argc) {
            server_run(pm_atoi(argv[++i])); io_exit(0);
#ifndef _WIN32
        } else if (!pm_strcmp(argv[i], "--daemon") && i+1 < argc) {
            long pid = sys1(SYS_FORK, 0);
            if (pid > 0) io_exit(0);
            if (pid == 0) { sys1(SYS_SETSID, 0); server_run(pm_atoi(argv[++i])); }
            io_exit(0);
#endif
        } else if (!pm_strcmp(argv[i], "-h") && i+1 < argc) {
            host_ip = parse_ip(argv[++i]);
        } else if (!pm_strcmp(argv[i], "-p") && i+1 < argc) {
            port = pm_atoi(argv[++i]);
        } else if (!cmd) { cmd = argv[i]; }
        else if (!arg) { arg = argv[i]; }
    }

    if (!host_ip || !cmd) { io_print(2, "Error: -h <host> and command required\n"); io_exit(1); }
    client_run(host_ip, port, cmd, arg);
}

#ifdef _WIN32

/* Windows: use GetCommandLineA + parse manually, or link with -lkernel32 -lws2_32 */
void mainCRTStartup(void) {
    win_init();
    /* Parse command line manually */
    char *cmdline = GetCommandLineA();
    static char *argv[64];
    int argc = 0;
    char *p = cmdline;
    while (*p && argc < 63) {
        while (*p == ' ') p++;
        if (!*p) break;
        if (*p == '"') { p++; argv[argc++] = p; while (*p && *p != '"') p++; }
        else { argv[argc++] = p; while (*p && *p != ' ') p++; }
        if (*p) *p++ = 0;
    }
    /* Get HOME from USERPROFILE */
    static char home[260];
    DWORD hl = GetEnvironmentVariableA("USERPROFILE", home, 260);
    if (hl == 0) { home[0] = 'C'; home[1] = ':'; home[2] = 0; }
    pmash_run(argc, argv, home);
}

#elif defined(__COSMOPOLITAN__)

/* Cosmopolitan: standard main() provided by cosmo libc */
int main(int argc, char **argv) {
    const char *home = getenv("HOME");
    if (!home) home = getenv("USERPROFILE");
    if (!home) home = "/tmp";
    pmash_run(argc, argv, home);
    return 0;
}

#else /* Linux (no libc) */

__attribute__((used)) void pmash_main(long *stack);

__attribute__((naked)) void _start(void) {
    __asm__("mov %rsp, %rdi\n\tjmp pmash_main");
}

__attribute__((used)) void pmash_main(long *stack) {
    int argc = (int)stack[0];
    char **argv = (char**)(stack + 1);
    char **envp = argv + argc + 1;
    const char *home = "/tmp";
    for (char **e = envp; *e; e++) {
        if (pm_memcmp(*e, "HOME=", 5) == 0) { home = *e + 5; break; }
    }
    pmash_run(argc, argv, home);
}

#endif
