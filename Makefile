# pmash — Makefile (multi-file C, no libc, LTO)
#
# Build: make          → pmash (stripped)
# Test:  make test     → run E2E
# Clean: make clean

CC = gcc
CFLAGS = -Os -fno-stack-protector -fno-builtin -nostdlib -static \
         -ffunction-sections -fdata-sections -fno-unwind-tables \
         -fno-asynchronous-unwind-tables -flto -Isrc
LDFLAGS = -Wl,--gc-sections -flto -nostdlib -static
STRIP = strip

SRCS = src/main.c src/util.c src/proto.c src/auth.c src/safety.c \
       src/sync.c src/tunnel.c src/compress.c src/server.c src/client.c
OBJS = $(SRCS:.c=.o)

.PHONY: all test clean

all: pmash

pmash: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^
	$(STRIP) $@
	@echo "Built: $@ ($$(wc -c < $@) bytes)"

src/%.o: src/%.c src/sys.h
	$(CC) $(CFLAGS) -c -o $@ $<

test: pmash
	@echo "Uploading and testing on build-server..."
	@scp pmash build-server:/tmp/pmash_test 2>/dev/null && \
	ssh build-server 'chmod +x /tmp/pmash_test && /tmp/pmash_test --version'

clean:
	rm -f pmash src/*.o
