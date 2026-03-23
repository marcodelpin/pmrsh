# pmrsh — Makefile (multi-file C, no libc, LTO)
#
# Build plain:    make              → pmrsh (~18KB)
# Build with TLS: make tls          → pmrsh (~150KB, needs BearSSL)
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

COSMOCC ?= $(HOME)/cosmocc/bin/cosmocc

.PHONY: all tls windows ape test clean

all: pmrsh

pmrsh: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^
	$(STRIP) $@
	@echo "Built: $@ ($$(wc -c < $@) bytes)"

tls: CFLAGS += -DHAS_TLS -I$(BEARSSL_INC) -D_FORTIFY_SOURCE=0
tls: clean $(OBJS)
	$(CC) $(LDFLAGS) -o pmrsh $(OBJS) $(BEARSSL_LIB)
	$(STRIP) pmrsh
	@echo "Built: pmrsh ($$(wc -c < pmrsh) bytes) [TLS]"

src/%.o: src/%.c src/sys.h
	$(CC) $(CFLAGS) -c -o $@ $<

# Cross-compile for Windows (MinGW) with icon
windows:
	x86_64-w64-mingw32-windres res/pmrsh.rc -O coff -o res/pmrsh.res
	x86_64-w64-mingw32-gcc -Os -fno-stack-protector -ffunction-sections -fdata-sections \
		-fno-unwind-tables -fno-asynchronous-unwind-tables -flto -Isrc -D_WIN32 \
		-nostartfiles -Wl,--gc-sections -s \
		-o pmrsh.exe $(SRCS) res/pmrsh.res -lws2_32 -lkernel32
	@echo "Built: pmrsh.exe ($$(wc -c < pmrsh.exe) bytes)"

# APE: vtable polyglot — single binary for Linux + Windows (with TLS + icon)
ape: ape2/mkape
	$(CC) -Os -fno-stack-protector -fno-builtin -nostdlib -static \
		-DHAS_TLS -I$(BEARSSL_INC) -D_FORTIFY_SOURCE=0 \
		-include ape2/sys_vtable.h -T ape2/ape.ld \
		-o ape2/pmrsh.elf ape2/vtable_rt.c ape2/main_ape.c ape2/tls_ape.c \
		$(filter-out src/main.c src/util.c src/tls.c,$(SRCS)) $(BEARSSL_LIB)
	./ape2/mkape ape2/pmrsh.elf -icon res/pmrsh.ico -o pmrsh.exe
	$(STRIP) pmrsh.exe
	@echo "Built: pmrsh.exe ($$(wc -c < pmrsh.exe) bytes) [APE+TLS+icon]"

ape2/mkape: ape2/mkape.c
	$(CC) -O2 -o $@ $<

test: pmrsh
	@./pmrsh --version

clean:
	rm -f pmrsh pmrsh.exe src/*.o res/*.res
