/* ed25519_wrap.c — thin wrapper around TweetNaCl for MASM linking */
/* Exports: Ed25519Sign, Ed25519Verify, Ed25519Keypair */
/* Compile: cl /c /O2 /nologo /Gs- /Zl ed25519_wrap.c tweetnacl.c */
/* /Gs- = no stack probes, /Zl = omit default lib name in .obj */

#include "tweetnacl.h"

/* Avoid CRT dependency — use Windows API directly */
typedef unsigned long ULONG;
typedef unsigned char BYTE;
typedef void *HANDLE;
#define BCRYPT_USE_SYSTEM_PREFERRED_RNG 0x00000002
#define NULL ((void*)0)
__declspec(dllimport) long __stdcall BCryptGenRandom(HANDLE, BYTE*, ULONG, ULONG);

/* memcpy/memset via RtlMoveMemory/RtlFillMemory (kernel32) */
__declspec(dllimport) void __stdcall RtlMoveMemory(void*, const void*, unsigned long);
__declspec(dllimport) void __stdcall RtlFillMemory(void*, unsigned long, unsigned char);

void *memcpy(void *d, const void *s, unsigned int n) {
    RtlMoveMemory(d, s, n); return d;
}
void *memset(void *d, int c, unsigned int n) {
    RtlFillMemory(d, n, (unsigned char)c); return d;
}

/* 64-bit integer helpers are in libcmt.lib — link with it */
/* Or better: use ntdll.lib which has _allmul etc. */

void randombytes(unsigned char *buf, unsigned long long len) {
    BCryptGenRandom(NULL, buf, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
}

/* Ed25519 sign: signs message m (mlen bytes) with secret key sk (64 bytes).
   Output: sm (signed message = 64-byte sig + m), smlen.
   For mrsh: we sign the challenge directly (not prefixed). */
__declspec(dllexport) int __stdcall
Ed25519Sign(unsigned char *sig_out,       /* 64 bytes output */
            const unsigned char *msg,      /* message to sign */
            unsigned long msg_len,
            const unsigned char *sk)       /* 64-byte secret key */
{
    unsigned char sm[65536];  /* signed message (sig + msg) */
    unsigned long long smlen = 0;
    if (msg_len > 65000) return -1;

    int ret = crypto_sign_ed25519_tweet(sm, &smlen, msg, msg_len, sk);
    if (ret != 0) return -1;

    /* Extract 64-byte signature from beginning of sm */
    memcpy(sig_out, sm, 64);
    return 0;
}

/* Ed25519 verify: verifies sig (64 bytes) on msg using pk (32 bytes).
   Returns 0 if valid, -1 if invalid. */
__declspec(dllexport) int __stdcall
Ed25519Verify(const unsigned char *sig,    /* 64-byte signature */
              const unsigned char *msg,     /* message */
              unsigned long msg_len,
              const unsigned char *pk)      /* 32-byte public key */
{
    unsigned char sm[65536];
    unsigned char m[65536];
    unsigned long long mlen = 0;
    if (msg_len > 65000) return -1;

    /* Reconstruct signed message: sig + msg */
    memcpy(sm, sig, 64);
    memcpy(sm + 64, msg, msg_len);

    int ret = crypto_sign_ed25519_tweet_open(m, &mlen, sm, 64 + msg_len, pk);
    return (ret == 0) ? 0 : -1;
}

/* Ed25519 keypair: generate new keypair.
   pk_out: 32 bytes, sk_out: 64 bytes. */
__declspec(dllexport) int __stdcall
Ed25519Keypair(unsigned char *pk_out, unsigned char *sk_out)
{
    return crypto_sign_ed25519_tweet_keypair(pk_out, sk_out);
}
