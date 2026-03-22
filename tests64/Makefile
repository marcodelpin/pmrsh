# pmash x86_64 tests — build and run on Linux x86_64
# Build: make         (compile all)
# Test:  make test    (compile + run all)
# Clean: make clean

NASM = nasm
LD = ld
CC = gcc
NASMFLAGS = -f elf64 -I../os/ -I../common64/
LDFLAGS = -z noexecstack
CFLAGS = -m64 -c -Os -fno-stack-protector -fno-builtin -nostdlib -I../common/

TESTS = test_hash test_pb test_b64 test_proto

.PHONY: all test clean main

all: $(TESTS)

# Main binary
main: pmash
pmash: ../os/main64.asm ../os/vtable64.inc ../os/linux64.inc ../common64/*.inc ed25519_linux64.o
	$(NASM) -f elf64 -I../os/ -I../common64/ -o pmash.o ../os/main64.asm
	$(LD) $(LDFLAGS) -o pmash pmash.o ed25519_linux64.o

ed25519_linux64.o: ../common64/ed25519_linux64.c ../common/tweetnacl.h ../common/tweetnacl.c
	$(CC) $(CFLAGS) -o tweetnacl.o ../common/tweetnacl.c
	$(CC) $(CFLAGS) -o ed25519_linux64.o ../common64/ed25519_linux64.c
	ld -r -o $@ ed25519_linux64.o tweetnacl.o

test: all
	@pass=0; fail=0; \
	for t in $(TESTS); do \
		echo "=== $$t ==="; \
		./$$t; \
		if [ $$? -eq 0 ]; then pass=$$((pass+1)); else fail=$$((fail+1)); fi; \
	done; \
	echo ""; \
	echo "Results: $$pass passed, $$fail failed"

test_%: test_%.asm ../os/vtable64.inc ../os/linux64.inc ../common64/*.inc
	$(NASM) $(NASMFLAGS) -o $@.o $<
	$(LD) $(LDFLAGS) -o $@ $@.o

clean:
	rm -f $(TESTS) pmash *.o
