# Solved Issues — mrsh-asm

## 2026-03

| ID | Date | Title | Severity | Area |
|----|------|-------|----------|------|
| [001](solved/2026-03-21-001-tls-single-record.md) | 2026-03-21 | TLS multi-record split causes command loss after auth | Critical | tls.inc |
| [002](solved/2026-03-21-002-proto-null-termination.md) | 2026-03-21 | Protocol payload not null-terminated — trailing garbage | High | proto.inc |
| [003](solved/2026-03-21-003-dangling-test-jnz.md) | 2026-03-21 | Dangling test/jnz rejects all TLS connections | Critical | main.asm |
| [004](solved/2026-03-21-004-lstrcpya-push-corruption.md) | 2026-03-21 | lstrcpyA corrupts TLS state — push 0 bytes | High | server.inc |
