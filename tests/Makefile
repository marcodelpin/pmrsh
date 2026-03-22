# pmash unified tests — build and run on Linux x86 (32-bit ELF)
# Build: make         (compile all)
# Test:  make test    (compile + run all)
# Clean: make clean

NASM = nasm
LD = ld
NASMFLAGS = -f elf32 -Ios/ -Icommon/ -I../os/ -I../common/
LDFLAGS = -m elf_i386 -s -z noexecstack

TESTS = test_hash test_pb test_b64 test_proto

.PHONY: all test clean

all: $(TESTS)

test: all
	@pass=0; fail=0; \
	for t in $(TESTS); do \
		echo "=== $$t ==="; \
		./$$t; \
		if [ $$? -eq 0 ]; then pass=$$((pass+1)); else fail=$$((fail+1)); fi; \
	done; \
	echo ""; \
	echo "Results: $$pass passed, $$fail failed"

test_%: test_%.asm ../os/vtable.inc ../os/linux.inc ../common/*.inc
	$(NASM) $(NASMFLAGS) -I../os/ -I../common/ -o $@.o $<
	$(LD) $(LDFLAGS) -o $@ $@.o

clean:
	rm -f $(TESTS) *.o
