/* ed25519_linux64.c — Linux x86_64 wrapper for TweetNaCl Ed25519 (no libc) */

#include "tweetnacl.h"

/* Inline syscalls for x86_64 Linux (no libc dependency) */
static long _syscall3(long nr, long a, long b, long c) {
    long ret;
    register long r10 __asm__("r10") = 0;
    __asm__ volatile("syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a), "S"(b), "d"(c), "r"(r10)
        : "rcx", "r11", "memory");
    return ret;
}
static long _syscall2(long nr, long a, long b) {
    long ret;
    __asm__ volatile("syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a), "S"(b)
        : "rcx", "r11", "memory");
    return ret;
}
static long _syscall1(long nr, long a) {
    long ret;
    __asm__ volatile("syscall"
        : "=a"(ret)
        : "a"(nr), "D"(a)
        : "rcx", "r11", "memory");
    return ret;
}

#define SYS_READ  0
#define SYS_OPEN  2
#define SYS_CLOSE 3
#define O_RDONLY  0

void *memcpy(void *d, const void *s, unsigned long n) {
    unsigned char *dd = d; const unsigned char *ss = s;
    while (n--) *dd++ = *ss++;
    return d;
}

void *memset(void *d, int c, unsigned long n) {
    unsigned char *dd = d;
    while (n--) *dd++ = (unsigned char)c;
    return d;
}

void randombytes(unsigned char *buf, unsigned long long len) {
    long fd = _syscall2(SYS_OPEN, (long)"/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        _syscall3(SYS_READ, fd, (long)buf, (long)len);
        _syscall1(SYS_CLOSE, fd);
    }
}

int Ed25519Sign(unsigned char *sig, const unsigned char *msg,
                unsigned long long msg_len, const unsigned char *sk) {
    unsigned char sm[16384];
    unsigned long long smlen;
    if (msg_len > 16000) return -1;
    crypto_sign_ed25519_tweet(sm, &smlen, msg, msg_len, sk);
    memcpy(sig, sm, 64);
    return 0;
}

int Ed25519Verify(const unsigned char *sig, const unsigned char *msg,
                  unsigned long long msg_len, const unsigned char *pk) {
    unsigned char sm[16384], m[16384];
    unsigned long long mlen;
    if (msg_len > 16000) return -1;
    memcpy(sm, sig, 64);
    memcpy(sm + 64, msg, msg_len);
    return crypto_sign_ed25519_tweet_open(m, &mlen, sm, msg_len + 64, pk);
}

int Ed25519Keypair(unsigned char *pk, unsigned char *sk) {
    crypto_sign_ed25519_tweet_keypair(pk, sk);
    return 0;
}
