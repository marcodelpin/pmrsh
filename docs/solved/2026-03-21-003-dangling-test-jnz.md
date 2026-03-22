# SOLVED: Dangling test/jnz rejects all TLS connections when auth disabled

| Metadata | Value |
| :--- | :--- |
| **Date** | 2026-03-21 |
| **ID** | 2026-03-21-003 |
| **Area** | main.asm / ServerLoop |
| **Status** | Resolved |
| **Impact** | Critical |

## 1. Problem Description

After commenting out `invoke AuthServerHandshake`, all TLS connections were silently rejected. Server log showed `[auth] rejected` for every connection. No auth code was running.

## 2. Root Cause Analysis (RCA)

When auth was disabled by commenting out the `invoke`, the subsequent `test eax, eax; jnz @sl_auth_fail` was left active. At that point, `eax` held the return value of `LogMsg` (which calls `WriteFile` → returns non-zero on success). The non-zero eax triggered `jnz @sl_auth_fail`, rejecting every connection.

```asm
;; Broken: invoke commented but test/jnz left active
;; invoke  AuthServerHandshake, ADDR clientTls
test    eax, eax          ; eax = LogMsg return (non-zero!)
jnz     @sl_auth_fail     ; always jumps → all connections rejected
```

## 3. Abstract Solution

When commenting out an `invoke`, always also comment out the corresponding `test/jnz` error check. Better: use a conditional assembly flag rather than commenting individual lines.

## 4. Prevention Rules

- When disabling a function call, comment out the ENTIRE error-check block (invoke + test + jnz), not just the invoke
- After commenting code, trace what `eax` contains at each point — `eax` from a prior call may trigger unintended branches
- Consider using MASM `IF/ENDIF` for compile-time feature toggles instead of comments

## 5. Case Study Reference

Commit 09e9472. Took 2 hours to find because the symptom ("auth rejected" in log) pointed at the auth module, but auth wasn't running. The actual cause was a register state leak from an unrelated function.
