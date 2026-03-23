# pmash — Makefile for C build (no libc, static)
#
# Build: make          → pmash (stripped, ~18KB)
# Test:  make test     → run E2E tests
# Clean: make clean

CC = gcc
CFLAGS = -Os -fno-stack-protector -fno-builtin -nostdlib -static \
         -ffunction-sections -fdata-sections -Wl,--gc-sections \
         -fno-unwind-tables -fno-asynchronous-unwind-tables
STRIP = strip

.PHONY: all test clean

all: pmash

pmash: src/pmash.c
	$(CC) $(CFLAGS) -o $@ $<
	$(STRIP) $@
	@echo "Built: $@ ($$(wc -c < $@) bytes)"

test: pmash
	@cp pmash tests64/pmash_c 2>/dev/null || true
	@echo "Running E2E tests..."
	@PMASH=./pmash bash tests64/test_e2e.sh

clean:
	rm -f pmash
