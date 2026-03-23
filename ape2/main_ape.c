/* main_ape.c — Entry point for vtable-based unified binary */
#include "sys_vtable.h"

#define VERSION "pmash 0.2.0 (ape-vtable)\n"
#define USAGE   "Usage: pmash -h <host> [-p <port>] <cmd> [arg]\n" \
                "       pmash --listen <port>\n" \
                "       pmash --version\n"

/* Entry point — when linked standalone, _start is here.
 * When linked with polyglot.S, polyglot provides _start and calls pmash_main. */
#ifndef POLYGLOT_HEADER
__attribute__((naked)) void _start(void) {
    __asm__("mov %rsp, %rdi\n\tjmp pmash_main");
}
#endif

void pmash_main(long *stack) {
    /* Init OS detection + vtable */
    detect_os();
    patch_vtable();

    int argc = (int)stack[0];
    char **argv = (char**)(stack + 1);

    /* Resolve HOME */
    char **envp = argv + argc + 1;
    const char *home = "/tmp";
    for (char **e = envp; *e; e++) {
        if (pm_memcmp(*e, "HOME=", 5) == 0) { home = *e + 5; break; }
    }
    auth_resolve_paths(home);
    tls_init(home);
    config_init(home);
    known_hosts_init(home);

    if (argc < 2) { io_print(2, USAGE); io_exit(1); }

    uint32_t host_ip = 0;
    uint16_t port = 8822;
    const char *cmd = 0, *arg = 0;

    for (int i = 1; i < argc; i++) {
        if (!pm_strcmp(argv[i], "--version")) { io_print(1, VERSION); io_exit(0); }
        else if (!pm_strcmp(argv[i], "--listen") && i+1 < argc) {
            server_run(pm_atoi(argv[++i])); io_exit(0);
        }
        else if (!pm_strcmp(argv[i], "-h") && i+1 < argc) host_ip = parse_ip(argv[++i]);
        else if (!pm_strcmp(argv[i], "-p") && i+1 < argc) port = pm_atoi(argv[++i]);
        else if (!cmd) cmd = argv[i];
        else if (!arg) arg = argv[i];
    }

    if (!host_ip || !cmd) { io_print(2, "Error: -h <host> and command required\n"); io_exit(1); }
    client_run(host_ip, port, cmd, arg);
}
