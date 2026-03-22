# SOLVED: TLS multi-record split causes command loss after auth handshake

| Metadata | Value |
| :--- | :--- |
| **Date** | 2026-03-21 |
| **ID** | 2026-03-21-001 |
| **Area** | tls.inc / TlsSendLenPrefixed |
| **Status** | Resolved |
| **Impact** | Critical |

## 1. Problem Description

After ECDSA auth handshake (4-message exchange), all subsequent command responses were empty. Server processed commands and sent responses, but client received nothing. Auth worked over plaintext (`--plain`), failed only over TLS.

## 2. Root Cause Analysis (RCA)

`TlsSendLenPrefixed` sent the 4-byte length header and payload as **two separate TLS records** (two `TlsSend` calls → two `EncryptMessage` calls). During multi-message exchanges, the receiver accumulated `SECBUFFER_EXTRA` data across `DecryptMessage` calls. The extra-data tracking in `TlsRecv` drifted, causing the 5th+ message's `DecryptMessage` to fail silently.

## 3. Abstract Solution

Combine the length header and payload into a **single buffer** before calling `TlsSend`. One `EncryptMessage` → one TLS record on the wire. No record splitting, no SECBUFFER_EXTRA accumulation across messages.

```asm
;; Before (broken): 2 TLS records
invoke TlsSend, pCtx, ADDR hdr, 4      ; record 1
invoke TlsSend, pCtx, lpBuf, nLen      ; record 2

;; After (fixed): 1 TLS record
;; Combine [hdr][payload] into pCombined buffer
invoke TlsSend, pCtx, pCombined, cbCombined
```

## 4. Prevention Rules

- Never send length prefix and payload as separate TLS records
- When implementing length-prefixed protocols over TLS, always combine into single encrypt/send
- Test multi-message TLS exchanges (not just single request-response)

## 5. Case Study Reference

Commit f541d0b. Discovered after auth worked over plaintext but failed over TLS. Debug showed server sent challenge OK (step 3), client recv failed. Root cause found by analyzing TlsSendLenPrefixed's two-call pattern.
