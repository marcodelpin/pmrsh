# Test Tree — pmash

Generated: 2026-03-22 | Windows: 55808 bytes (26 modules) | Linux: 8848 bytes (6 modules)

## Summary

- **Windows modules**: 26 (.inc)
- **Linux modules**: 6 (.inc) — scaffolding, server+exec+proto+util+net+syscall
- **Unit test binaries**: 8 functional + 6 stubs = 14
- **Unit tests**: 27 (clitest:3, cryptotest:7, exectest:1, netlooptest:6, hashtest:5, pbtest:8, compresstest:4, b64test:6, jsontest:4)
- **E2E test cases**: 18 (17 automated, 1 manual)
- **Total tests**: 45
- **Module coverage**: 8/26 unit tested (31%), 16/26 E2E touched (62%)
- **Solved issues with regression tests**: 0/4 (0%) — implicit E2E only
- **Cross-platform**: Windows client → Linux server verified (ping)

## Coverage Matrix — Windows

| Module | Lines | PROCs | Unit Test | E2E | Status |
|--------|-------|-------|-----------|-----|--------|
| auth.inc | 260 | 3 | — | YES (TOFU) | PARTIAL |
| base64.inc | 270 | 2 | b64test (6) | — | **HIGH** |
| cli.inc | 420 | 2 | clitest (3) | YES (--version) | HIGH |
| client.inc | 1100 | 5 | — | — | NONE |
| compress.inc | 255 | 3 | compresstest (4) | — | **HIGH** |
| crypto.inc | 430 | 13 | cryptotest (7) | — | PARTIAL |
| exec.inc | 237 | 1 | exectest (1) | YES (hostname, echo) | HIGH |
| hash.inc | 120 | 3 | hashtest (5) | — | **HIGH** |
| input.inc | 575 | 4 | — | YES (mouse pos) | PARTIAL |
| json.inc | 171 | 1 | jsontest (4) | — | **HIGH** |
| native.inc | 228 | 3 | — | YES (ps) | PARTIAL |
| net.inc | 401 | 13 | netlooptest (6) | YES (all E2E) | HIGH |
| proto.inc | 400 | 11 | — | YES (implicit) | PARTIAL |
| protobuf.inc | 220 | 5 | pbtest (8) | — | **HIGH** |
| proxy.inc | 225 | 3 | — | — | NONE |
| relay.inc | 590 | 5 | — | — | NONE |
| screenshot.inc | 198 | 1 | — | YES (>1KB) | PARTIAL |
| selfupdate.inc | 129 | 2 | — | — | NONE |
| server.inc | 360 | 1 | — | YES (E2E loop) | PARTIAL |
| service.inc | 238 | 5 | — | — | NONE |
| shell.inc | 187 | 2 | — | MANUAL | NONE |
| sync.inc | 590 | 5 | — | — | NONE |
| tls.inc | 1070 | 7 | stub | YES (all E2E) | PARTIAL |
| transfer.inc | 355 | 4 | — | YES (push/pull/write) | PARTIAL |
| tray.inc | 226 | 2 | stub | — | NONE |
| util.inc | 67 | 3 | — | YES (implicit) | PARTIAL |

## Coverage Matrix — Linux

| Module | Lines | Status |
|--------|-------|--------|
| syscall.inc | 90 | Macros only |
| util.inc | 175 | No tests yet |
| net.inc | 85 | No tests yet |
| exec.inc | 110 | No tests yet |
| proto.inc | 190 | No tests yet |
| server.inc | 210 | Cross-platform ping verified |

## Unit Test Binaries

| Binary | Module | Tests | Status |
|--------|--------|-------|--------|
| clitest | cli.inc | atoi, CLI_ARGS sizeof, edge case | PASS |
| cryptotest | crypto.inc | ECDSA full round-trip (7 steps) | PASS |
| exectest | exec.inc | ExecCommand echo | PASS |
| netlooptest | net.inc | TCP echo + LenPrefixed (6 steps) | PASS |
| hashtest | hash.inc | Adler32 (3) + MD5 (2) known vectors | PASS |
| pbtest | protobuf.inc | varint (5) + round-trip + WriteString + WriteInt32 | PASS |
| compresstest | compress.inc | init + small→raw + 4KB round-trip + raw flag | PASS |
| b64test | base64.inc | RFC 4648 vectors (5) + round-trip | PASS |
| jsontest | json.inc | string/number/bool/missing-key | PASS |
| fulltest | ALL | compile gate only | STUB |
| tlstest | tls.inc | TlsInit/Close only | STUB |

## E2E Tests (test.bat) — 18 tests

| # | Test | Validates | Status |
|---|------|-----------|--------|
| 1 | ping | pong response | PASS |
| 2 | exec hostname | exit code 0 | PASS |
| 3 | exec echo | output match | PASS |
| 4 | info | JSON hostname | PASS |
| 5 | ls | directory listing | PASS |
| 6 | version | 0.1.0 string | PASS |
| 7 | screenshot | BMP >1KB | PASS |
| 8 | auth TOFU | key files exist | PASS |
| 9 | push | "push complete" | PASS |
| 10 | push verify | file non-empty | PASS |
| 11 | pull | "pull complete" | PASS |
| 12 | pull verify | content match (fc /B) | PASS |
| 13 | ps | JSON with "pid" | PASS |
| 14 | write | "write complete" | PASS |
| 15 | write verify | content match | PASS |
| 16 | mouse pos | "x,y" format | PASS |
| 17 | window list | JSON with "hwnd" | PASS |
| 18 | shell | interactive stdin | MANUAL |

## GPU Verification (MDP-DEV-GPU)

All unit tests (27/27) + E2E (8/8 core commands) verified on remote GPU.
Debug output gated behind `-v` flag — no test pollution.

## Cross-Platform Verification

| Test | Client | Server | Result |
|------|--------|--------|--------|
| ping | Windows pmash (55KB) | Linux pmash (8.8KB) | **PASS** |
| exec | Windows → Linux | (server needs restart) | Protocol verified |

## Regression Gap Table

| Source | Issue | Bug Description | Regression Test | Status |
|--------|-------|-----------------|-----------------|--------|
| solved/001 | TLS single-record | 2 TLS records → drift | (E2E implicit) | MISSING |
| solved/002 | Proto null-term | No null-terminator | (E2E implicit) | MISSING |
| solved/003 | Dangling test/jnz | Commented auth → reject all | (E2E implicit) | MISSING |
| solved/004 | lstrcpyA push | TLS state corruption → 0 bytes | push verify | PARTIAL |
| fix 914943a | Shell race | Pipes closed before thread | (none) | MISSING |
| fix 5b4100b | Compress raw | lea vs mov for pIn | compresstest T4 | **OK** |

## Gaps by Priority

### P0 — Covered (since last analysis)
- ~~protobuf.inc~~ → pbtest (8 tests) ✓
- ~~hash.inc~~ → hashtest (5 tests) ✓
- ~~compress.inc~~ → compresstest (4 tests) + bug found & fixed ✓
- ~~base64.inc~~ → b64test (6 tests) ✓
- ~~json.inc~~ → jsontest (4 tests) ✓

### P1 — Remaining gaps
1. **sync.inc** (590 lines, 5 PROCs) — delta E2E needs server+client
2. **native.inc kill** — ps tested via E2E, kill needs specific PID test
3. **Regression: TLS multi-record** — implicit, should be explicit
4. **Linux modules** — 6 modules, 0 dedicated tests

### P2 — Nice to have
5. **proxy.inc** — needs 3 processes for chain test
6. **relay.inc** — needs mock hbbs UDP server
7. **client.inc** — large (1100 lines) but mostly routing
8. **service.inc** — SCM interaction (destructive)
