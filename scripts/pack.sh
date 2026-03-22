#!/bin/bash
# =============================================================================
# pack.sh — Generate self-extracting pmash installer
# Part of pmash — lightweight remote agent
# =============================================================================
# Usage:
#   ./pack.sh --platform linux  [--key <pubkey_file>] [--port 8822] [-o output]
#   ./pack.sh --platform windows [--key <pubkey_file>] [--port 8822] [-o output]
#
# Linux output:  pmash-<version>-linux-install.sh  (self-extracting)
# Windows output: pmash-<version>-windows-install.exe (NSIS, needs makensis)
# =============================================================================

set -e

VERSION="0.2.0"
PLATFORM=""
PORT=8822
OUTPUT=""
KEYS=()
BINARY=""
RDV_SERVER=""
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --platform) PLATFORM="$2"; shift 2 ;;
        --port|-p)  PORT="$2"; shift 2 ;;
        --key|-k)   KEYS+=("$2"); shift 2 ;;
        --binary)   BINARY="$2"; shift 2 ;;
        --rdv)      RDV_SERVER="$2"; shift 2 ;;
        -o)         OUTPUT="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 --platform linux|windows [--key pubkey] [--port 8822] [-o output]"
            echo ""
            echo "Options:"
            echo "  --platform  Target platform: linux or windows"
            echo "  --key       Path to Ed25519 public key file (can specify multiple)"
            echo "  --port      Port for pmash service (default: 8822)"
            echo "  --binary    Path to pmash binary (auto-detected if not specified)"
            echo "  --rdv       Rendezvous server address (host:port)"
            echo "  -o          Output file path"
            exit 0
            ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ -z "$PLATFORM" ]]; then
    echo "Error: --platform required (linux or windows)"
    exit 1
fi

# Find binary
find_binary() {
    if [[ -n "$BINARY" && -f "$BINARY" ]]; then
        echo "$BINARY"
        return
    fi

    local name="pmash"
    [[ "$PLATFORM" == "windows" ]] && name="pmash.exe"

    # Check common locations
    for p in \
        "$PROJECT_DIR/$name" \
        "$PROJECT_DIR/tests64/$name" \
        "$PROJECT_DIR/asm/build/$name" \
        "./$name"; do
        if [[ -f "$p" ]]; then
            echo "$p"
            return
        fi
    done

    echo "Error: cannot find pmash binary. Use --binary to specify." >&2
    exit 1
}

BINARY_PATH=$(find_binary)
BINARY_SIZE=$(stat -c%s "$BINARY_PATH" 2>/dev/null || stat -f%z "$BINARY_PATH" 2>/dev/null)
echo "  binary: $(basename "$BINARY_PATH") ($BINARY_SIZE bytes)"

# Build authorized_keys
build_authorized_keys() {
    local tmpkeys=$(mktemp)

    # Collect specified keys
    for keyfile in "${KEYS[@]}"; do
        if [[ -f "$keyfile" ]]; then
            cat "$keyfile" >> "$tmpkeys"
            echo "" >> "$tmpkeys"
        else
            echo "Warning: key file not found: $keyfile" >&2
        fi
    done

    # If no keys specified, try default locations
    if [[ ${#KEYS[@]} -eq 0 ]]; then
        for default_key in \
            "$HOME/.ssh/id_ed25519.pub" \
            "$HOME/.pmash/id_ed25519.pub" \
            "/etc/pmash/id_ed25519.pub"; do
            if [[ -f "$default_key" ]]; then
                cat "$default_key" >> "$tmpkeys"
                echo "" >> "$tmpkeys"
            fi
        done
    fi

    # Deduplicate
    sort -u "$tmpkeys" | grep -v '^$'
    rm -f "$tmpkeys"
}

AUTH_KEYS=$(build_authorized_keys)
KEY_COUNT=$(echo "$AUTH_KEYS" | grep -c '.' || echo 0)
echo "  authorized_keys: $KEY_COUNT key(s)"

# =============================================================================
# Linux: self-extracting .sh
# =============================================================================
generate_linux() {
    local outfile="${OUTPUT:-pmash-${VERSION}-linux-install.sh}"

    # Generate inner install.sh
    local install_script="#!/bin/bash
set -e

echo \"=== pmash Installer (v${VERSION}) ===\"
echo \"Port: ${PORT}\"
echo

if [ \"\$(id -u)\" -ne 0 ]; then
    echo \"ERROR: Run as root: sudo \$0\"
    exit 1
fi

# Install binary
install -m 755 \"\$(dirname \"\$0\")/pmash\" /usr/local/bin/pmash
echo \"Binary installed: /usr/local/bin/pmash\"

# Install keys
mkdir -p /etc/pmash
install -m 600 \"\$(dirname \"\$0\")/authorized_keys\" /etc/pmash/authorized_keys
echo \"Config directory: /etc/pmash\"

# Create systemd service
cat > /etc/systemd/system/pmash.service << 'UNIT'
[Unit]
Description=pmash remote agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/pmash --listen ${PORT}
Restart=always
RestartSec=5
KillSignal=SIGTERM

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now pmash
echo \"Service started.\"

# Install avahi for DNS auto-discovery
if command -v apt >/dev/null 2>&1; then
    apt install -y avahi-daemon 2>/dev/null && systemctl enable --now avahi-daemon || true
elif command -v apk >/dev/null 2>&1; then
    apk add avahi && rc-update add avahi-daemon default && rc-service avahi-daemon start || true
fi

echo
echo \"=== Installation complete ===\"
echo \"pmash listening on port ${PORT}\"
echo \"Connect with: pmash -h \$(hostname) ping\"
"

    # Build tar.gz payload
    local tmpdir=$(mktemp -d)
    trap "rm -rf '$tmpdir'" EXIT

    cp "$BINARY_PATH" "$tmpdir/pmash"
    chmod 755 "$tmpdir/pmash"
    echo "$AUTH_KEYS" > "$tmpdir/authorized_keys"
    chmod 600 "$tmpdir/authorized_keys"
    echo "$install_script" > "$tmpdir/install.sh"
    chmod 755 "$tmpdir/install.sh"

    local tar_payload=$(mktemp)
    (cd "$tmpdir" && tar czf "$tar_payload" pmash authorized_keys install.sh)

    # Write self-extracting script
    cat > "$outfile" << 'SFX_HEADER'
#!/bin/bash
# pmash — Self-extracting installer
set -e

echo "=== pmash Installer ==="

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: Run as root: sudo $0"
    exit 1
fi

TMPDIR=$(mktemp -d /tmp/pmash-install.XXXXXX)
trap "rm -rf '$TMPDIR'" EXIT

ARCHIVE=$(awk '/^__ARCHIVE_BELOW__$/ {print NR + 1; exit 0;}' "$0")
tail -n+"$ARCHIVE" "$0" | tar xzf - -C "$TMPDIR"

cd "$TMPDIR"
chmod +x install.sh
./install.sh

exit 0
__ARCHIVE_BELOW__
SFX_HEADER

    # Append tar.gz payload as binary
    cat "$tar_payload" >> "$outfile"
    chmod 755 "$outfile"
    rm -f "$tar_payload"

    local size=$(stat -c%s "$outfile" 2>/dev/null || stat -f%z "$outfile" 2>/dev/null)
    local size_kb=$((size / 1024))
    echo ""
    echo "Install pack ready: $outfile (${size_kb} KB)"
    echo "Deploy: scp $outfile target: && ssh target 'chmod +x $outfile && sudo ./$outfile'"
}

# =============================================================================
# Windows: NSIS installer
# =============================================================================
generate_windows() {
    local outfile="${OUTPUT:-pmash-${VERSION}-windows-install.exe}"

    # Find makensis
    local makensis=""
    for candidate in makensis makensis.exe \
        /usr/bin/makensis /usr/local/bin/makensis \
        "C:/Program Files (x86)/NSIS/makensis.exe" \
        "C:/Program Files/NSIS/makensis.exe"; do
        if command -v "$candidate" >/dev/null 2>&1 || [[ -f "$candidate" ]]; then
            makensis="$candidate"
            break
        fi
    done

    if [[ -z "$makensis" ]]; then
        echo "Error: makensis not found. Install NSIS:"
        echo "  Ubuntu: sudo apt install nsis"
        echo "  Windows: scoop install nsis"
        exit 1
    fi
    echo "  nsis: $makensis"

    local tmpdir=$(mktemp -d)
    trap "rm -rf '$tmpdir'" EXIT

    # Copy files to staging
    cp "$BINARY_PATH" "$tmpdir/pmash.exe"
    echo "$AUTH_KEYS" > "$tmpdir/authorized_keys"

    # Generate install.bat
    cat > "$tmpdir/install.bat" << INSTALLBAT
@echo off
setlocal
echo === pmash Installer (v${VERSION}) ===
echo Port: ${PORT}
echo.

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Run as Administrator.
    pause
    exit /b 1
)

echo Stopping existing services...
net stop pmash >nul 2>&1
net stop mrsh >nul 2>&1
sc delete pmash >nul 2>&1
taskkill /F /IM pmash.exe >nul 2>&1
timeout /t 2 /nobreak >nul

set DATADIR=C:\\ProgramData\\pmash
if not exist "%DATADIR%" mkdir "%DATADIR%"

copy /Y "%~dp0pmash.exe" "%DATADIR%\\pmash.exe"
copy /Y "%~dp0authorized_keys" "%DATADIR%\\authorized_keys"

echo Installing service...
"%DATADIR%\\pmash.exe" --install --port ${PORT}

echo Configuring firewall...
netsh advfirewall firewall delete rule name="pmash" >nul 2>&1
netsh advfirewall firewall add rule name="pmash" dir=in action=allow protocol=TCP localport=${PORT}

echo Starting service...
net start pmash

echo.
echo === Installation complete ===
echo pmash listening on port ${PORT}
INSTALLBAT

    # Generate NSIS script
    cat > "$tmpdir/installer.nsi" << 'NSIEOF'
!include "MUI2.nsh"

Name "pmash ${VERSION}"
OutFile "${OUTFILE}"
InstallDir "$PROGRAMDATA\pmash"
RequestExecutionLevel admin
ShowInstDetails show

!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Section "Install"
    SetOutPath $INSTDIR

    ; Stop existing
    nsExec::ExecToStack 'net stop pmash'
    Pop $0
    nsExec::ExecToStack 'net stop mrsh'
    Pop $0
    nsExec::ExecToStack 'sc delete pmash'
    Pop $0
    nsExec::ExecToStack 'taskkill /F /IM pmash.exe'
    Pop $0
    Sleep 2000

    ; Install files
    File "pmash.exe"
    File "authorized_keys"

    ; Install service
    nsExec::ExecToStack '"$INSTDIR\pmash.exe" --install --port ${PORT}'
    Pop $0
    DetailPrint "Service installed."

    ; Firewall
    nsExec::ExecToStack 'netsh advfirewall firewall delete rule name="pmash"'
    Pop $0
    nsExec::ExecToStack 'netsh advfirewall firewall add rule name="pmash" dir=in action=allow protocol=TCP localport=${PORT}'
    Pop $0
    DetailPrint "Firewall rule added."

    ; Start
    nsExec::ExecToStack 'net start pmash'
    Pop $0
    DetailPrint "Service started on port ${PORT}."
SectionEnd
NSIEOF

    # Replace variables in NSI
    sed -i "s/\${VERSION}/${VERSION}/g; s/\${PORT}/${PORT}/g; s|\${OUTFILE}|${outfile}|g" "$tmpdir/installer.nsi"

    # Compile
    echo "  nsis: compiling installer..."
    (cd "$tmpdir" && "$makensis" -V2 installer.nsi)

    if [[ -f "$tmpdir/$outfile" ]]; then
        mv "$tmpdir/$outfile" "$outfile"
    fi

    local size=$(stat -c%s "$outfile" 2>/dev/null || stat -f%z "$outfile" 2>/dev/null)
    local size_kb=$((size / 1024))
    echo ""
    echo "Install pack ready: $outfile (${size_kb} KB)"
    echo "Deploy: copy to target and run as Administrator."
}

# =============================================================================
# Main
# =============================================================================

echo "=== pmash pack v${VERSION} ==="
echo "  platform: $PLATFORM"
echo "  port: $PORT"

case "$PLATFORM" in
    linux)   generate_linux ;;
    windows) generate_windows ;;
    *)
        echo "Error: unknown platform '$PLATFORM' (use linux or windows)"
        exit 1
        ;;
esac
