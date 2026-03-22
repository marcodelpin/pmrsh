# Test Tree — mrsh-asm

Generated: 2026-03-21 | Binary: 25088 bytes | 15 modules | 4785 LOC

## Summary

| Metric | Value |
|--------|-------|
| Total PROCs | 71 |
| Tested (functional) | 12 (16.9%) |
| Partially tested (init/compile only) | 8 (11.3%) |
| Untested | 51 (71.8%) |
| Test files | 8 (examples/*.asm) |
| E2E verified commands | ping, exec, info, ls, screenshot |

## Coverage Matrix

### crypto.inc (12 PROCs — 7 tested)

| PROC | Test | Status | Cost |
|------|------|--------|------|
| CryptoInit | cryptotest | TESTED | FREE |
| CryptoCleanup | cryptotest | TESTED | FREE |
| CryptoGenKey | cryptotest | TESTED | FREE |
| CryptoSign | cryptotest | TESTED | FREE |
| CryptoVerify | cryptotest | TESTED | FREE |
| CryptoHashSHA256 | cryptotest | TESTED | FREE |
| CryptoExportKey | cryptotest | TESTED | FREE |
| CryptoImportKey | cryptotest | TESTED | FREE |
| CryptoRandom | — | MISSING | FREE |
| CryptoSaveKey | — | MISSING | FREE |
| CryptoLoadKey | — | MISSING | FREE |
| BytesToHex | — | MISSING | FREE |

### cli.inc (2 PROCs — 0 tested) **P0**

| PROC | Test | Status | Cost |
|------|------|--------|------|
| CliParse | — | MISSING | FREE |
| _atoi_simple | — | MISSING | FREE |

### net.inc (14 PROCs — 2 tested)

| PROC | Test | Status | Cost |
|------|------|--------|------|
| NetInit | nettest | TESTED | FREE |
| NetCleanup | nettest | TESTED | FREE |
| NetConnect | — | MISSING | CHEAP |
| NetListen | — | MISSING | CHEAP |
| NetAccept | — | MISSING | CHEAP |
| NetSend/Recv | — | MISSING | CHEAP |
| NetSendAll/RecvAll | — | MISSING | CHEAP |
| NetClose | — | MISSING | CHEAP |
| NetSendLenPrefixed | — | MISSING | CHEAP |
| NetRecvLenPrefixed | — | MISSING | CHEAP |
| NetSetTimeout | — | MISSING | CHEAP |

### exec.inc (1 PROC — partial)

| PROC | Test | Status | Cost |
|------|------|--------|------|
| ExecCommand | exectest | PARTIAL (no output check) | CHEAP |

### tls.inc (9 PROCs — 2 partial)

| PROC | Test | Status | Cost |
|------|------|--------|------|
| TlsInit | tlstest | PARTIAL (init only) | MODERATE |
| TlsClose | tlstest | PARTIAL (no connection) | MODERATE |
| TlsConnect | — | MISSING | MODERATE |
| TlsAccept | — | MISSING | MODERATE |
| TlsSend/Recv | — | MISSING | MODERATE |

### proto.inc (8 PROCs — 0 tested)

All tested indirectly via E2E (ping/exec/info work), but no dedicated unit tests.

### auth.inc (2 PROCs — 0 tested) **BLOCKED**

Auth handshake disabled due to TLS SECBUFFER_EXTRA issue. Crypto primitives work (cryptotest passes all 7 steps).

### transfer.inc (4 PROCs — 0 tested)

Untested. Push/pull not E2E verified yet.

### screenshot.inc (1 PROC — 0 tested)

ScreenCapture untested standalone. Works via E2E (server dispatch verified).

### service.inc (5 PROCs — 0 tested)

Requires admin privileges. Not safely unit testable.

### tray.inc (2 PROCs — 0 tested)

GUI; requires manual interaction. Not automatable.

### selfupdate.inc (2 PROCs — 0 tested)

Dangerous (file replacement). Staging test only.

## Regression Gap Table

| Source | Commit | Bug Description | Regression Test | Status |
|--------|--------|-----------------|-----------------|--------|
| fix | 6b6d4ca | TLS credential leak (shared cred freed per-client) | — | MISSING |
| fix | 6b6d4ca | TOFU saves but never compares keys | — | MISSING |
| fix | fe2c500 | Entry point: --console -p ignored (flags after positional) | — | MISSING |
| fix | fe2c500 | Console mode hardcoded DEFAULT_PORT | — | MISSING |
| fix | 1e9e2c5 | Auth TLS buffer corruption (SECBUFFER_EXTRA) | — | BLOCKED |
| fix | f7988b5 | fulltest link error (missing ServerLoop) | fulltest.asm | OK |

## Test Cost Summary

| Cost | Count | Notes |
|------|-------|-------|
| FREE | 18 | Pure logic: crypto, cli, atoi, hex conversion |
| CHEAP | 22 | Local I/O: net loopback, exec, screenshot, file transfer |
| MODERATE | 15 | TLS handshake, auth, proto over TLS |
| HIGH | 7 | Service SCM, selfupdate, tray GUI |

## Priority Gaps

1. **P0 — CliParse unit test** (FREE, pure logic, 0% coverage, most testable)
2. **P0 — Net loopback test** (CHEAP, validates connect→send→recv→close)
3. **P0 — ExecCommand output verification** (CHEAP, existing test is stub)
4. **P1 — ScreenCapture standalone** (CHEAP, verifies BMP generation)
5. **P1 — E2E test script** (bat/ps1 automation of loopback suite)
6. **P1 — Regression: flag priority fix** (verify --console -p works)
7. **P2 — Transfer push/pull** (needs client+server)
8. **BLOCKED — Auth handshake** (needs TLS buffer fix first)
