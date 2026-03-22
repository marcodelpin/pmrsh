# SOLVED: lstrcpyA corrupts TLS state — push writes 0 bytes

| Metadata | Value |
| :--- | :--- |
| **Date** | 2026-03-21 |
| **ID** | 2026-03-21-004 |
| **Area** | server.inc / push handler |
| **Status** | Resolved |
| **Impact** | High |

## 1. Problem Description

After modularizing main.asm into server.inc, push always wrote 0 bytes. Server created file but TransferHandlePush's ProtoRecvMsg for PUSH_DATA chunks returned -1.

## 2. Root Cause Analysis (RCA)

The push handler called lstrcpyA to copy the remote path from msg.pData to a global buffer (_srvCmdBuf) before calling ProtoFreeMsg and CreateFileA. This lstrcpyA call somehow corrupted the TLS context state, causing subsequent ProtoRecvMsg to fail.

Exact mechanism unclear — possibly lstrcpyA clobbered a register used by the TLS layer, or the global buffer address conflicted with the TLS recv buffer.

## 3. Abstract Solution

Use the path directly from msg.pData for CreateFileA (before freeing the message). Don't copy strings to global buffers when the original is still valid. Free the message after the path is no longer needed.

## 4. Prevention Rules

- Avoid unnecessary string copies — use the original buffer when available
- Test push/pull after any modularization change (high regression risk)
- When extracting code to .inc files, verify all global variable references

## 5. Case Study Reference

Commit c1f815d. Confirmed by testing: without lstrcpyA → push works, with lstrcpyA → 0 bytes.
