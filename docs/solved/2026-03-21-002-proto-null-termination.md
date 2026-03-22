# SOLVED: Protocol payload not null-terminated — exec commands have trailing garbage

| Metadata | Value |
| :--- | :--- |
| **Date** | 2026-03-21 |
| **ID** | 2026-03-21-002 |
| **Area** | proto.inc / ProtoRecvMsg |
| **Status** | Resolved |
| **Impact** | High |

## 1. Problem Description

`mrsh -h host exec hostname` produced `hostnameg?^` — the command had random trailing bytes. The garbage changed between runs (uninitialized memory).

## 2. Root Cause Analysis (RCA)

`ProtoRecvMsg` allocated exactly `dataLen` bytes for the payload via `GlobalAlloc`, then copied `dataLen` bytes from the wire buffer. No null terminator was appended. Downstream code (ExecCommand, lstrcpyA, wsprintfA) treated the payload as a C string and read past the allocated buffer into uninitialized heap memory.

## 3. Abstract Solution

Allocate `dataLen + 1` bytes and write a null byte at position `dataLen` after the memcpy. Also preserve `edi`/`ebx` across `invoke RtlMoveMemory` (MASM `invoke` clobbers caller-saved registers).

## 4. Prevention Rules

- Always allocate +1 and null-terminate any buffer that may be used as a string
- When using MASM `invoke`, save register values in callee-saved registers (ebx/esi/edi) before the call, not push/pop around it (invoke clobbers ecx/edx)

## 5. Case Study Reference

Commit 7cbf54c. The garbage was different each run because GlobalAlloc returns zeroed memory on first allocation but reuses freed blocks (with stale data) on subsequent calls.
