#!/bin/bash
# pmash x86_64 E2E test suite
# Run from tests64/ directory after building main binary

set -e

PMASH="../pmash"  # or wherever the binary is
PORT=19822
PASS=0
FAIL=0
TOTAL=0

cleanup() {
    kill $SERVER_PID 2>/dev/null || true
    rm -f /tmp/pmash_test_push /tmp/pmash_test_pull /tmp/pmash_test_write
}
trap cleanup EXIT

# Build if needed
if [ ! -f "$PMASH" ]; then
    echo "Building pmash..."
    cd .. && make -f tests64/Makefile main && cd tests64
    PMASH="../pmash"
fi

assert_eq() {
    TOTAL=$((TOTAL+1))
    local desc="$1" expected="$2" actual="$3"
    if [ "$expected" = "$actual" ]; then
        echo "  PASS [$desc]"
        PASS=$((PASS+1))
    else
        echo "  FAIL [$desc] expected='$expected' got='$actual'"
        FAIL=$((FAIL+1))
    fi
}

assert_contains() {
    TOTAL=$((TOTAL+1))
    local desc="$1" needle="$2" haystack="$3"
    if echo "$haystack" | grep -q "$needle"; then
        echo "  PASS [$desc]"
        PASS=$((PASS+1))
    else
        echo "  FAIL [$desc] '$needle' not in output"
        FAIL=$((FAIL+1))
    fi
}

assert_ok() {
    TOTAL=$((TOTAL+1))
    local desc="$1"
    if [ $? -eq 0 ]; then
        echo "  PASS [$desc]"
        PASS=$((PASS+1))
    else
        echo "  FAIL [$desc]"
        FAIL=$((FAIL+1))
    fi
}

echo "=== pmash x86_64 E2E Test Suite ==="
echo ""

# Start server
echo "[setup] Starting server on port $PORT..."
$PMASH --listen $PORT &
SERVER_PID=$!
sleep 1

# Verify server is listening
if ! ss -tlnp 2>/dev/null | grep -q ":$PORT"; then
    echo "FATAL: server not listening on port $PORT"
    exit 1
fi
echo "[setup] Server running (PID $SERVER_PID)"
echo ""

# --- Tests ---

echo "[e2e] ping"
OUT=$($PMASH -h 127.0.0.1 -p $PORT ping 2>&1)
assert_eq "ping returns pong" "pong" "$OUT"

echo "[e2e] exec hostname"
OUT=$($PMASH -h 127.0.0.1 -p $PORT exec "hostname" 2>&1)
EXPECTED=$(hostname)
assert_eq "exec hostname" "$EXPECTED" "$OUT"

echo "[e2e] exec echo"
OUT=$($PMASH -h 127.0.0.1 -p $PORT exec "echo hello_pmash" 2>&1)
assert_eq "exec echo" "hello_pmash" "$OUT"

echo "[e2e] info"
OUT=$($PMASH -h 127.0.0.1 -p $PORT info 2>&1)
assert_contains "info has hostname" "hostname" "$OUT"
assert_contains "info has version" "pmash" "$OUT"
assert_contains "info has os" "Linux" "$OUT"

echo "[e2e] ps"
OUT=$($PMASH -h 127.0.0.1 -p $PORT ps 2>&1)
assert_contains "ps lists processes" "pmash" "$OUT"

echo "[e2e] push file"
echo "test_content_12345" > /tmp/pmash_test_push
$PMASH -h 127.0.0.1 -p $PORT push /tmp/pmash_test_push 2>&1
assert_ok "push completes"

echo "[e2e] push verify"
CONTENT=$(cat /tmp/pmash_test_push 2>/dev/null)
assert_eq "pushed file has content" "test_content_12345" "$CONTENT"

echo "[e2e] pull file"
$PMASH -h 127.0.0.1 -p $PORT pull /tmp/pmash_test_push 2>&1
assert_ok "pull completes"

echo "[e2e] write file"
$PMASH -h 127.0.0.1 -p $PORT write "/tmp/pmash_test_write:hello_from_write" 2>&1
assert_ok "write completes"

echo "[e2e] write verify"
if [ -f /tmp/pmash_test_write ]; then
    CONTENT=$(cat /tmp/pmash_test_write)
    assert_eq "written file content" "hello_from_write" "$CONTENT"
else
    TOTAL=$((TOTAL+1))
    echo "  FAIL [write verify] file not created"
    FAIL=$((FAIL+1))
fi

echo "[e2e] shell"
OUT=$($PMASH -h 127.0.0.1 -p $PORT shell "echo shell_test_ok" 2>&1)
assert_contains "shell returns output" "shell_test_ok" "$OUT"

echo "[e2e] ls"
OUT=$($PMASH -h 127.0.0.1 -p $PORT exec "ls /tmp" 2>&1)
assert_contains "ls lists files" "pmash_test" "$OUT"

echo "[e2e] kill (dummy PID)"
OUT=$($PMASH -h 127.0.0.1 -p $PORT kill 999999 2>&1)
assert_contains "kill response" "kill" "$OUT"

echo "[e2e] version"
OUT=$($PMASH --version 2>&1)
assert_contains "version string" "pmash 0.2.0" "$OUT"

echo ""
echo "=== Results: $PASS/$TOTAL passed, $FAIL failed ==="
exit $FAIL
