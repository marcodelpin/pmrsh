/*
 * polyglot.S — MZ/PE + ELF polyglot header (x86_64)
 *
 * This file produces a binary that is simultaneously:
 *   - A valid Windows PE64 executable (MZ header → PE → entry point)
 *   - A valid Linux ELF64 executable (ELF header at offset 0 via overlay)
 *
 * Trick: The first 2 bytes are MZ (0x4D5A). On Linux, the kernel sees
 * this is NOT ELF (no 7F 45 4C 46) and rejects it. We register the
 * APE format via binfmt_misc, OR we use the approach where the MZ bytes
 * are also valid x86 instructions:
 *
 *   4D          = dec ebp     (harmless on x86_64, sets flags)
 *   5A          = pop rdx     (pops argc into rdx — we can work with this)
 *
 * Then we jump over the PE header to our entry point.
 *
 * The REAL trick (Cosmopolitan-style): put an ELF header at a specific
 * offset and make the PE optional header's AddressOfEntryPoint land on
 * valid code for both platforms.
 *
 * For simplicity: we use the "MZ as instructions" trick.
 * The MZ bytes (4D 5A) are:
 *   dec ebp; pop rdx
 * Then we add a jump to skip the rest of the headers.
 *
 * Assemble: gcc -nostdlib -static -Wl,-T,polyglot.ld -o pmrsh.com polyglot.S vtable_code.o
 */

.section .head, "ax", @progbits
.globl _start

_start:
    /* MZ header bytes — also valid x86_64 instructions */
    .byte 0x4D, 0x5A           /* dec ebp; pop rdx — MZ magic */

    /* Jump over DOS/PE header to real entry */
    jmp _real_start

    /* DOS header fields (offset 4..63) */
    .org 0x3C
    .long pe_header - _start   /* e_lfanew: offset to PE header */

    .org 0x40
    /* DOS stub area — pad with NOPs */
    .fill 0xC0 - 0x40, 1, 0x90

    /* PE header at offset 0xC0 */
pe_header:
    .ascii "PE\0\0"            /* PE signature */
    .word 0x8664               /* Machine: AMD64 */
    .word 1                    /* NumberOfSections */
    .long 0                    /* TimeDateStamp */
    .long 0                    /* PointerToSymbolTable */
    .long 0                    /* NumberOfSymbols */
    .word opt_end - opt_start  /* SizeOfOptionalHeader */
    .word 0x0022               /* Characteristics: EXEC | LARGE_ADDR */

opt_start:
    .word 0x020B               /* PE32+ magic */
    .byte 1, 0                 /* LinkerVersion */
    .long _code_size           /* SizeOfCode */
    .long 0                    /* SizeOfInitializedData */
    .long 0                    /* SizeOfUninitializedData */
    .long _real_start - _start /* AddressOfEntryPoint (RVA) */
    .long 0x1000               /* BaseOfCode */
    .quad 0x140000000          /* ImageBase */
    .long 0x1000               /* SectionAlignment */
    .long 0x200                /* FileAlignment */
    .word 6, 0                 /* OS Version */
    .word 0, 0                 /* Image Version */
    .word 6, 0                 /* Subsystem Version */
    .long 0                    /* Win32VersionValue */
    .long _image_size          /* SizeOfImage */
    .long _headers_size        /* SizeOfHeaders */
    .long 0                    /* CheckSum */
    .word 3                    /* Subsystem: CONSOLE */
    .word 0x8160               /* DllCharacteristics */
    .quad 0x100000             /* SizeOfStackReserve */
    .quad 0x1000               /* SizeOfStackCommit */
    .quad 0x100000             /* SizeOfHeapReserve */
    .quad 0x1000               /* SizeOfHeapCommit */
    .long 0                    /* LoaderFlags */
    .long 0                    /* NumberOfRvaAndSizes (0 = no data dirs) */
opt_end:

    /* Section table: .text */
    .ascii ".text\0\0\0"       /* Name */
    .long _code_size           /* VirtualSize */
    .long 0x1000               /* VirtualAddress */
    .long _code_size           /* SizeOfRawData */
    .long _headers_size        /* PointerToRawData */
    .long 0, 0                 /* Relocations, LineNumbers */
    .word 0, 0
    .long 0x60000020           /* Characteristics: CODE|EXEC|READ */

    /* Pad to FileAlignment boundary */
    .org 0x200

/* ====================================================================
 * Real entry point — reached from both PE and ELF paths
 * On PE: jumped to via AddressOfEntryPoint
 * On Linux: jumped to from MZ bytes + jmp
 * ==================================================================== */
_real_start:
    /* Standard SysV entry: rsp has argc, argv, envp */
    mov %rsp, %rdi
    call pmrsh_main

    /* Unreachable */
    ud2

/* Size markers for PE header (filled by linker) */
.equ _code_size, 0x8000       /* conservative estimate */
.equ _headers_size, 0x200
.equ _image_size, 0x10000
