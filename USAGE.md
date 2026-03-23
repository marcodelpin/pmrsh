# pmrsh — Lightweight Remote Agent

**176KB single binary** — runs on Linux and Windows from the same file.

## Quick Start

```bash
# Server (on target machine)
chmod +x pmrsh.exe    # Linux only
./pmrsh.exe --listen 8822

# Client (from any machine)
./pmrsh.exe -h <host> -p 8822 ping
./pmrsh.exe -h <host> exec "hostname"
```

## Commands

| Command | Example | Description |
|---|---|---|
| `ping` | `pmrsh -h host ping` | Connectivity check |
| `exec` | `pmrsh -h host exec "ls -la"` | Run command, get output |
| `info` | `pmrsh -h host info` | JSON: hostname, version, OS |
| `ps` | `pmrsh -h host ps` | Process list |
| `kill` | `pmrsh -h host kill 1234` | Kill process by PID |
| `push` | `pmrsh -h host push /path/file` | Upload file to server |
| `pull` | `pmrsh -h host pull /path/file` | Download file from server |
| `write` | `pmrsh -h host write "path:content"` | Create file with content |
| `cat` | `pmrsh -h host cat /path/file` | Read file content |
| `mkdir` | `pmrsh -h host mkdir /path/dir` | Create directory |
| `rm` | `pmrsh -h host rm /path/file` | Delete file |
| `stat` | `pmrsh -h host stat /path/file` | File size (8-byte LE) |
| `ls` | `pmrsh -h host ls /path` | List directory |
| `shell` | `pmrsh -h host shell "cmd"` | Execute in shell session |
| `sync` | `pmrsh -h host sync /path/file` | Delta pull (Adler32 blocks) |
| `sync-push` | `pmrsh -h host sync-push /path` | Delta push to server |
| `forward` | `pmrsh -h host forward 8080:target:80` | Port forwarding (-L) |
| `socks` | `pmrsh -h host socks 1080` | SOCKS5 proxy (-D) |
| `wol` | `pmrsh -h host wol aa:bb:cc:dd:ee:ff` | Wake-on-LAN |
| `reboot` | `pmrsh -h host reboot` | Reboot remote |
| `shutdown` | `pmrsh -h host shutdown` | Shutdown remote |
| `service` | `pmrsh -h host service list` | List systemd services |
| `session` | `pmrsh -h host session` | Interactive PTY |
| `batch` | `pmrsh -h host batch script.pmrsh` | Run batch script |

## Server Modes

```bash
pmrsh.exe --listen 8822        # Foreground server
pmrsh.exe --daemon 8822        # Background daemon (Linux)
pmrsh.exe --version            # Show version
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
  -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=pmrsh"
mkdir -p ~/.pmrsh/tls
openssl x509 -in cert.pem -outform DER -out ~/.pmrsh/tls/cert.der
openssl ec -in key.pem -outform DER -out ~/.pmrsh/tls/key.der
```

TLS activates automatically when cert files exist. Protocol detection (first byte 0x16) allows mixed plain/TLS clients.

## Authentication

Ed25519 TOFU (Trust On First Use). Keys auto-generated at `~/.pmrsh/id_ed25519{,.pub}` on first connection.

## Config File

`~/.pmrsh/config` (SSH-style):
```
Host myserver
    HostName 192.168.1.10
    Port 9822
    MAC aa:bb:cc:dd:ee:ff
```

## Safety

The server blocks self-destructive commands:
- `killall pmrsh`, `pkill pmrsh`
- `systemctl stop pmrsh`, `service pmrsh stop`
- `rm /usr/local/bin/pmrsh`

Rate limiting: 5 failed auth attempts → 5 minute ban.

## Install (Linux)

```bash
chmod +x pmrsh.exe
sudo cp pmrsh.exe /usr/local/bin/pmrsh
sudo cat > /etc/systemd/system/pmrsh.service << EOF
[Unit]
Description=pmrsh remote agent
After=network.target
[Service]
Type=simple
ExecStart=/usr/local/bin/pmrsh --listen 8822
Restart=always
[Install]
WantedBy=multi-user.target
EOF
sudo systemctl enable --now pmrsh
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
