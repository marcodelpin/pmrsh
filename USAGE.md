# pmash — Lightweight Remote Agent

**176KB single binary** — runs on Linux and Windows from the same file.

## Quick Start

```bash
# Server (on target machine)
chmod +x pmash.exe    # Linux only
./pmash.exe --listen 8822

# Client (from any machine)
./pmash.exe -h <host> -p 8822 ping
./pmash.exe -h <host> exec "hostname"
```

## Commands

| Command | Example | Description |
|---|---|---|
| `ping` | `pmash -h host ping` | Connectivity check |
| `exec` | `pmash -h host exec "ls -la"` | Run command, get output |
| `info` | `pmash -h host info` | JSON: hostname, version, OS |
| `ps` | `pmash -h host ps` | Process list |
| `kill` | `pmash -h host kill 1234` | Kill process by PID |
| `push` | `pmash -h host push /path/file` | Upload file to server |
| `pull` | `pmash -h host pull /path/file` | Download file from server |
| `write` | `pmash -h host write "path:content"` | Create file with content |
| `cat` | `pmash -h host cat /path/file` | Read file content |
| `mkdir` | `pmash -h host mkdir /path/dir` | Create directory |
| `rm` | `pmash -h host rm /path/file` | Delete file |
| `stat` | `pmash -h host stat /path/file` | File size (8-byte LE) |
| `ls` | `pmash -h host ls /path` | List directory |
| `shell` | `pmash -h host shell "cmd"` | Execute in shell session |
| `sync` | `pmash -h host sync /path/file` | Delta pull (Adler32 blocks) |
| `sync-push` | `pmash -h host sync-push /path` | Delta push to server |
| `forward` | `pmash -h host forward 8080:target:80` | Port forwarding (-L) |
| `socks` | `pmash -h host socks 1080` | SOCKS5 proxy (-D) |
| `wol` | `pmash -h host wol aa:bb:cc:dd:ee:ff` | Wake-on-LAN |
| `reboot` | `pmash -h host reboot` | Reboot remote |
| `shutdown` | `pmash -h host shutdown` | Shutdown remote |
| `service` | `pmash -h host service list` | List systemd services |
| `session` | `pmash -h host session` | Interactive PTY |
| `batch` | `pmash -h host batch script.pmash` | Run batch script |

## Server Modes

```bash
pmash.exe --listen 8822        # Foreground server
pmash.exe --daemon 8822        # Background daemon (Linux)
pmash.exe --version            # Show version
```

## Options

| Flag | Description |
|---|---|
| `-h <host>` | Server IP address |
| `-p <port>` | Port (default: 8822, auto-tries 8822→9822→22) |

## TLS

Generate server certificate (first time):
```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=pmash"
mkdir -p ~/.pmash/tls
openssl x509 -in cert.pem -outform DER -out ~/.pmash/tls/cert.der
openssl ec -in key.pem -outform DER -out ~/.pmash/tls/key.der
```

TLS activates automatically when cert files exist. Protocol detection (first byte 0x16) allows mixed plain/TLS clients.

## Authentication

Ed25519 TOFU (Trust On First Use). Keys auto-generated at `~/.pmash/id_ed25519{,.pub}` on first connection.

## Config File

`~/.pmash/config` (SSH-style):
```
Host myserver
    HostName 192.168.1.10
    Port 9822
    MAC aa:bb:cc:dd:ee:ff
```

## Safety

The server blocks self-destructive commands:
- `killall pmash`, `pkill pmash`
- `systemctl stop pmash`, `service pmash stop`
- `rm /usr/local/bin/pmash`

Rate limiting: 5 failed auth attempts → 5 minute ban.

## Install (Linux)

```bash
chmod +x pmash.exe
sudo cp pmash.exe /usr/local/bin/pmash
sudo cat > /etc/systemd/system/pmash.service << EOF
[Unit]
Description=pmash remote agent
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/pmash --listen 8822
Restart=always
[Install]
WantedBy=multi-user.target
EOF
sudo systemctl enable --now pmash
```

Or use the installer: `scripts/pack.sh --platform linux --port 8822`

## Architecture

Single C codebase, no libc, vtable-based OS abstraction:
- **Linux**: inline `syscall` instruction
- **Windows**: PEB → kernel32.dll → export table → ms_abi thunks
- **OS detection**: dual entry point (ELF `_start` vs PE `entry_pe`)
- **TLS**: BearSSL linked statically
- **Binary format**: MZ/PE header + embedded ELF (polyglot)

## Build

```bash
make              # Linux-only (25KB)
make tls          # Linux + TLS (116KB)
make windows      # Windows cross-compile (280KB)
make ape          # Polyglot (176KB, both OS, TLS, icon)
```

## Wire Protocol

`[4-byte BE length][1-byte cmdId][payload]` — compatible with mrsh.
