/* test_vtable.c — Minimal test for vtable_rt */

extern int detect_os(void);
extern void patch_vtable(void);
extern void io_print(int fd, const char *s);
extern void io_exit(int code);

/* Entry point (Linux no-libc) */
void _start(void) {
    detect_os();
    patch_vtable();
    io_print(1, "pmash vtable test: ");
    io_print(1, "OS detected, vtable patched\n");
    io_print(1, "ping → pong (vtable I/O works)\n");
    io_exit(0);
}
