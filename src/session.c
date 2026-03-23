/* session.c — PTY sessions, session recording, batch scripting */
#include "sys.h"

#define SYS_OPENPTY  /* not a real syscall — use /dev/ptmx + ptsname */
#define CMD_SESSION_OPEN    0x82
#define CMD_SESSION_DATA    0x83
#define CMD_SESSION_CLOSE   0x84

/* === PTY session (Linux pseudo-terminal) === */

#define PTMX_PATH "/dev/ptmx"

static int pty_open(int *master_fd) {
    /* Open ptmx */
    int mfd = (int)sys3(SYS_OPEN, (long)PTMX_PATH, O_RDWR, 0);
    if (mfd < 0) return -1;
    /* grantpt + unlockpt via ioctl */
    /* TIOCSPTLCK = 0x40045431 (unlock) */
    int unlock = 0;
    sys3(16/*SYS_IOCTL*/, mfd, 0x40045431, (long)&unlock);
    *master_fd = mfd;
    /* Get slave pts number */
    int ptsn = 0;
    sys3(16, mfd, 0x80045430/*TIOCGPTN*/, (long)&ptsn);
    /* Build /dev/pts/N path */
    static char pts_path[32] = "/dev/pts/";
    char tmp[8]; int ti = 7; tmp[7] = 0;
    int n = ptsn; if (n == 0) tmp[--ti] = '0';
    while (n > 0) { tmp[--ti] = '0' + (n % 10); n /= 10; }
    pm_memcpy(pts_path + 9, tmp + ti, 7 - ti + 1);
    int sfd = (int)sys3(SYS_OPEN, (long)pts_path, O_RDWR, 0);
    return sfd;
}

/* Server: handle interactive PTY session */
void session_handle(int cfd) {
    int mfd, sfd;
    sfd = pty_open(&mfd);
    if (sfd < 0) {
        proto_send_msg(cfd, CMD_ERROR, "pty failed", 10);
        return;
    }

    long pid = sys1(SYS_FORK, 0);
    if (pid == 0) {
        /* Child: set up PTY as stdin/stdout/stderr */
        io_close(mfd);
        sys1(SYS_SETSID, 0);
        sys3(16, sfd, 0x540E/*TIOCSCTTY*/, 0); /* set controlling terminal */
        sys2(SYS_DUP2, sfd, 0);
        sys2(SYS_DUP2, sfd, 1);
        sys2(SYS_DUP2, sfd, 2);
        if (sfd > 2) io_close(sfd);
        const char *argv[] = { "/bin/bash", "-l", 0 };
        sys3(SYS_EXECVE, (long)"/bin/bash", (long)argv, 0);
        const char *argv2[] = { "/bin/sh", 0 };
        sys3(SYS_EXECVE, (long)"/bin/sh", (long)argv2, 0);
        io_exit(127);
    }

    io_close(sfd);
    /* Parent: relay PTY master ↔ network client */
    proxy_forward(cfd, mfd);
    sys2(SYS_KILL, pid, SIGKILL);
    sys4(SYS_WAIT4, pid, 0, 0, 0);
    io_close(mfd);
}

/* === Session recording (asciicast v2 format) === */

static int rec_fd = -1;
static long rec_start_sec = 0;

void recording_start(const char *path) {
    rec_fd = io_open(path, 1);
    if (rec_fd < 0) return;
    /* Header */
    const char *hdr = "{\"version\":2,\"width\":80,\"height\":24,\"title\":\"pmash\"}\n";
    io_write(rec_fd, hdr, pm_strlen(hdr));
    /* TODO: get actual time for timestamps */
    rec_start_sec = 0;
}

void recording_write(const void *data, int len) {
    if (rec_fd < 0) return;
    /* asciicast event: [time, "o", "data"] */
    char line[512] = "[0.0, \"o\", \"";
    int n = pm_strlen(line);
    /* Escape data */
    const char *d = data;
    for (int i = 0; i < len && n < 500; i++) {
        if (d[i] == '"') { line[n++] = '\\'; line[n++] = '"'; }
        else if (d[i] == '\\') { line[n++] = '\\'; line[n++] = '\\'; }
        else if (d[i] == '\n') { line[n++] = '\\'; line[n++] = 'n'; }
        else if (d[i] == '\r') { line[n++] = '\\'; line[n++] = 'r'; }
        else if (d[i] >= 32) line[n++] = d[i];
    }
    line[n++] = '"'; line[n++] = ']'; line[n++] = '\n';
    io_write(rec_fd, line, n);
}

void recording_stop(void) {
    if (rec_fd >= 0) { io_close(rec_fd); rec_fd = -1; }
}

/* === Batch scripting (.pmash files) === */

int batch_exec(int server_fd, const char *script_path) {
    int fd = io_open(script_path, 0);
    if (fd < 0) return -1;
    char buf[8192];
    int n = io_read(fd, buf, sizeof(buf) - 1);
    io_close(fd);
    if (n <= 0) return -1;
    buf[n] = 0;

    /* Execute line by line */
    char *p = buf;
    int lines = 0;
    while (*p) {
        /* Find end of line */
        char *eol = p;
        while (*eol && *eol != '\n') eol++;
        char saved = *eol; *eol = 0;

        /* Skip empty/comment lines */
        if (*p && *p != '#') {
            /* Send as exec */
            int cl = pm_strlen(p);
            char cmd[65536];
            cmd[0] = cl >> 8; cmd[1] = cl & 0xFF;
            pm_memcpy(cmd + 2, p, cl);
            cmd[2 + cl] = 0;
            proto_send_msg(server_fd, CMD_EXEC, cmd, 3 + cl);
            /* Recv result */
            int ml = proto_recv_msg(server_fd);
            if (ml > 9 && proto_buf[0] == CMD_EXEC_RESULT) {
                io_write(1, proto_buf + 9, ml - 9);
            }
            lines++;
        }

        *eol = saved;
        p = (*eol) ? eol + 1 : eol;
    }
    return lines;
}
