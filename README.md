# pmash

Lightweight remote agent written in pure assembly. No runtime dependencies.

| Platform | Assembler | Binary | Dependencies |
|----------|-----------|--------|-------------|
| Windows x86 | MASM | 55 KB | Zero (no CRT) |
| Linux x86_64 | NASM | 8.8 KB | Zero (no libc) |

## Features

- **Remote execution** — exec, shell, ps, kill
- **File transfer** — push, pull, write, cat, ls
- **Delta sync** — block-level rsync (Adler32 + MD5 signatures, M/D/E protocol)
- **GUI automation** — mouse (move/click/scroll), keyboard (type/tap), window (list/find/activate/close)
- **Screenshot** — GDI screen capture (Windows), sent as BMP
- **Relay** — NAT traversal via hbbs rendezvous (protobuf over UDP)
- **ProxyJump** — tunnel through intermediate host (`-J proxy -h target`)
- **Compression** — LZNT1 via ntdll (Windows), zero external deps
- **TLS 1.2/1.3** — SChannel (Windows), no OpenSSL
- **Ed25519 auth** — TweetNaCl, challenge-response, TOFU
- **Service** — Windows service + tray icon, auto-start

## Build

### Windows (MASM)

Requires Visual Studio Build Tools with C++ workload.

```batch
cd asm
build.bat src\main              # GUI subsystem (service/tray)
build.bat src\main -console     # Console (testing)
```

### Linux (NASM)

```bash
cd linux
make    # produces 'pmash' static binary
```

## Usage

```
pmash -h <host> exec <cmd>
pmash -h <host> push <local> <remote>
pmash -h <host> pull <remote> <local>
pmash -h <host> write <local> <remote>
pmash -h <host> sync <remote> <local>
pmash -h <host> sync-push <local> <remote>
pmash -h <host> ps | kill <pid>
pmash -h <host> mouse pos|move|click|scroll [args]
pmash -h <host> key type|tap <text|key>
pmash -h <host> window list|find|activate|close [args]
pmash -h <host> screenshot [file.bmp]
pmash -h <host> info | ping | shell
pmash -J <proxy> -h <target> exec <cmd>
pmash -d <device_id> -r <rdv_server> exec <cmd>
pmash --install | --uninstall
pmash --listen <port>
pmash --version
```

## Wire Protocol

Binary framing: `[4-byte BE length][1-byte cmd_id][payload]`

Compatible with [mrsh](https://github.com/marcodelpin/mrsh) Rust implementation — same command IDs, same auth handshake, same delta sync M/D/E markers.

## Architecture

22 modules (Windows), 6 modules (Linux):

| Module | Function |
|--------|----------|
| cli | Argument parsing |
| net | TCP socket operations |
| tls | SChannel TLS 1.2/1.3 (Windows) |
| crypto | ECDSA-P256 via BCrypt (Windows) |
| auth | Ed25519 via TweetNaCl |
| proto | Binary wire protocol |
| protobuf | Minimal protobuf encoder for hbbs |
| exec | Command execution |
| transfer | File push/pull |
| sync | Delta sync (Adler32 + MD5 block signatures) |
| native | Process list/kill (Toolhelp32) |
| input | GUI automation (SendInput) |
| screenshot | Screen capture (GDI) |
| shell | Interactive shell (bidirectional pipes) |
| relay | hbbs rendezvous (UDP protobuf) |
| proxy | ProxyJump tunneling |
| compress | LZNT1 compression (ntdll) |
| server | Accept loop + command dispatch |
| service | Windows SCM service |
| tray | System tray icon |
| selfupdate | Binary swap via schtasks |
| hash | Adler32 + MD5 |
| json | Minimal JSON parser |
| base64 | RFC 4648 encode/decode |
| util | String/IO helpers |

## Tests

```
Unit tests:   27 (9 test binaries)
E2E tests:    21 (20 automated, 1 manual)
Total:        48
Coverage:     31% unit, 62% E2E
```

## License

MIT
