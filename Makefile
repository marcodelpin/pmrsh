# pmash — Makefile (multi-file C, no libc, LTO)
#
# Build plain:    make              → pmash (~18KB)
# Build with TLS: make tls          → pmash (~150KB, needs BearSSL)
# Clean:          make clean

CC = gcc
CFLAGS = -Os -fno-stack-protector -fno-builtin -nostdlib -static \
         -ffunction-sections -fdata-sections -fno-unwind-tables \
         -fno-asynchronous-unwind-tables -flto -Isrc
LDFLAGS = -Wl,--gc-sections -flto -nostdlib -static
STRIP = strip

SRCS = src/main.c src/util.c src/proto.c src/auth.c src/safety.c \
       src/sync.c src/tunnel.c src/compress.c src/relay.c \
       src/config.c src/system.c src/session.c src/fleet.c \
       src/server.c src/client.c src/tls.c
OBJS = $(SRCS:.c=.o)

BEARSSL_INC ?= $(HOME)/bearssl/inc
BEARSSL_LIB ?= $(HOME)/bearssl/build/libbearssl.a

.PHONY: all tls windows test clean

all: pmash

pmash: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^
	$(STRIP) $@
	@echo "Built: $@ ($$(wc -c < $@) bytes)"

tls: CFLAGS += -DHAS_TLS -I$(BEARSSL_INC) -D_FORTIFY_SOURCE=0
tls: clean $(OBJS)
	$(CC) $(LDFLAGS) -o pmash $(OBJS) $(BEARSSL_LIB)
	$(STRIP) pmash
	@echo "Built: pmash ($$(wc -c < pmash) bytes) [TLS]"

src/%.o: src/%.c src/sys.h
	$(CC) $(CFLAGS) -c -o $@ $<

# Cross-compile for Windows (MinGW)
windows:
	x86_64-w64-mingw32-gcc -Os -fno-stack-protector -ffunction-sections -fdata-sections \
		-fno-unwind-tables -fno-asynchronous-unwind-tables -flto -Isrc -D_WIN32 \
		-nostartfiles -Wl,--gc-sections -s \
		-o pmash.exe $(SRCS) -lws2_32 -lkernel32
	@echo "Built: pmash.exe ($$(wc -c < pmash.exe) bytes)"

test: pmash
	@./pmash --version

clean:
	rm -f pmash pmash.exe src/*.o
