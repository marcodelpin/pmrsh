# pmash Linux — x86_64 NASM build
# Requires: nasm, ld (GNU linker)
# Output: pmash (static, no libc dependency)

NASM = nasm
LD = ld
NASMFLAGS = -f elf64 -Iinclude/
LDFLAGS = -s -static

SRC = src/main.asm
OBJ = src/main.o
BIN = pmash

.PHONY: all clean

all: $(BIN)

$(OBJ): $(SRC) $(wildcard include/*.inc)
	$(NASM) $(NASMFLAGS) -o $@ $<

$(BIN): $(OBJ)
	$(LD) $(LDFLAGS) -o $@ $<

clean:
	rm -f $(OBJ) $(BIN)
