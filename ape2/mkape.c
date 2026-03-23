/* mkape.c — Build a polyglot APE binary from ELF + PE resource
 *
 * Produces a file that is:
 *   1. A valid Windows PE (MZ header → PE → our code)
 *   2. A valid shell script (first line after MZ = #!/bin/sh handler)
 *
 * The PE header is crafted so that:
 *   - Windows PE loader maps .text section to our code
 *   - The MZ DOS stub contains a shell script that runs the ELF part
 *
 * Usage: mkape <elf_input> <pe_rsrc.res> <output.com>
 *
 * This is a BUILD TOOL — runs on the build host, not on targets.
 * Compile with system gcc: gcc -o mkape mkape.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Minimal PE structures */
#pragma pack(push, 1)

struct dos_header {
    uint16_t e_magic;      /* MZ */
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;     /* offset to PE header */
};

struct pe_header {
    uint32_t signature;    /* PE\0\0 */
    uint16_t machine;      /* 0x8664 = AMD64 */
    uint16_t num_sections;
    uint32_t timestamp;
    uint32_t symtab_ptr;
    uint32_t num_symbols;
    uint16_t opt_hdr_size;
    uint16_t characteristics;
};

struct pe_optional_64 {
    uint16_t magic;        /* 0x020B = PE32+ */
    uint8_t  major_linker;
    uint8_t  minor_linker;
    uint32_t code_size;
    uint32_t init_data_size;
    uint32_t uninit_data_size;
    uint32_t entry_rva;
    uint32_t code_base;
    uint64_t image_base;
    uint32_t section_align;
    uint32_t file_align;
    uint16_t os_major, os_minor;
    uint16_t img_major, img_minor;
    uint16_t subsys_major, subsys_minor;
    uint32_t win32_ver;
    uint32_t image_size;
    uint32_t headers_size;
    uint32_t checksum;
    uint16_t subsystem;    /* 3 = CONSOLE */
    uint16_t dll_chars;
    uint64_t stack_reserve, stack_commit;
    uint64_t heap_reserve, heap_commit;
    uint32_t loader_flags;
    uint32_t num_data_dirs;
    /* data directories follow */
};

struct section_header {
    char name[8];
    uint32_t virtual_size;
    uint32_t virtual_addr;
    uint32_t raw_size;
    uint32_t raw_ptr;
    uint32_t reloc_ptr;
    uint32_t linenum_ptr;
    uint16_t num_relocs;
    uint16_t num_linenums;
    uint32_t characteristics;
};

#pragma pack(pop)

#define FILE_ALIGN 512
#define SECT_ALIGN 4096
#define ALIGN(x, a) (((x) + (a) - 1) & ~((a) - 1))

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: mkape <elf_binary> <output.com>\n");
        return 1;
    }

    const char *elf_path = argv[1];
    const char *out_path = argv[2];

    /* Read ELF binary */
    FILE *f = fopen(elf_path, "rb");
    if (!f) { perror(elf_path); return 1; }
    fseek(f, 0, SEEK_END);
    long elf_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *elf_data = malloc(elf_size);
    fread(elf_data, 1, elf_size, f);
    fclose(f);
    printf("ELF: %s (%ld bytes)\n", elf_path, elf_size);

    /* === Build APE file === */

    /* Layout:
     * [0x000] DOS header (MZ) + shell script in DOS stub
     * [0x100] PE signature + PE header + optional header + section table
     * [0x200] .text section (our ELF code, raw — PE loader maps it)
     * [end]   shell script payload marker + ELF binary appended
     */

    /* DOS stub that doubles as shell script */
    char dos_stub[256];
    memset(dos_stub, 0, sizeof(dos_stub));

    /* MZ header */
    struct dos_header *dh = (struct dos_header *)dos_stub;
    dh->e_magic = 0x5A4D; /* MZ */
    dh->e_cblp = 0x0090;  /* these bytes = "\x90\x00" = NOP + NULL */
    dh->e_cp = 3;
    dh->e_cparhdr = 4;
    dh->e_maxalloc = 0xFFFF;
    dh->e_sp = 0x00B8;
    dh->e_lfarlc = 0x0040;
    dh->e_lfanew = 0x100;  /* PE header at offset 256 */

    /* Embed shell script in DOS stub (bytes 64..255) */
    /* This must be valid shell AND harmless to DOS */
    const char *shell_script =
        "# pmash APE\n"
        "e=pmash_$$;t=/tmp/$e\n"
        "s=$(awk '/^__ELF__$/{print NR+1;exit}' \"$0\")\n"
        "tail -n+$s \"$0\" > $t && chmod +x $t && exec $t \"$@\"\n"
        "exit 1\n";
    int script_len = strlen(shell_script);
    if (script_len > 190) {
        fprintf(stderr, "Shell script too long (%d > 190)\n", script_len);
        return 1;
    }
    memcpy(dos_stub + 64, shell_script, script_len);

    /* Build .text section = the code from ELF */
    /* For simplicity: extract .text from ELF, or just use the whole ELF
     * as a flat binary for the PE .text section.
     * The entry point offset needs to match. */

    /* For true APE: we'd need to extract machine code from ELF .text
     * and map it to PE .text at the right virtual address.
     * For now: create a PE that's basically a launcher,
     * and append the full ELF for the shell script to extract. */

    uint32_t code_size = ALIGN(elf_size, FILE_ALIGN);
    uint32_t headers_size = ALIGN(0x200, FILE_ALIGN); /* DOS + PE + sections */

    /* PE header at offset 0x100 */
    uint8_t pe_block[256];
    memset(pe_block, 0, sizeof(pe_block));

    struct pe_header *pe = (struct pe_header *)pe_block;
    pe->signature = 0x00004550; /* PE\0\0 */
    pe->machine = 0x8664;       /* AMD64 */
    pe->num_sections = 1;
    pe->opt_hdr_size = sizeof(struct pe_optional_64) + 16 * 8; /* 16 data dirs */
    pe->characteristics = 0x0022; /* EXECUTABLE | LARGE_ADDRESS_AWARE */

    struct pe_optional_64 *opt = (struct pe_optional_64 *)(pe_block + sizeof(struct pe_header));
    opt->magic = 0x020B;        /* PE32+ */
    opt->code_size = code_size;
    opt->entry_rva = 0x1000;    /* RVA of .text = entry */
    opt->code_base = 0x1000;
    opt->image_base = 0x140000000ULL;
    opt->section_align = SECT_ALIGN;
    opt->file_align = FILE_ALIGN;
    opt->os_major = 6;
    opt->subsys_major = 6;
    opt->image_size = ALIGN(0x1000 + code_size, SECT_ALIGN);
    opt->headers_size = headers_size;
    opt->subsystem = 3;         /* CONSOLE */
    opt->dll_chars = 0x8160;    /* DEP + ASLR + HIGHENTROPYVA + TERMINAL_SERVER */
    opt->stack_reserve = 0x100000;
    opt->stack_commit = 0x1000;
    opt->heap_reserve = 0x100000;
    opt->heap_commit = 0x1000;
    opt->num_data_dirs = 16;

    /* Section table (after optional header + data directories) */
    int sect_offset = sizeof(struct pe_header) + opt->opt_hdr_size;
    struct section_header *sect = (struct section_header *)(pe_block + sect_offset);
    memcpy(sect->name, ".text\0\0\0", 8);
    sect->virtual_size = elf_size;
    sect->virtual_addr = 0x1000;
    sect->raw_size = code_size;
    sect->raw_ptr = headers_size;
    sect->characteristics = 0x60000020; /* CODE | EXECUTE | READ */

    /* === Write output === */
    FILE *out = fopen(out_path, "wb");
    if (!out) { perror(out_path); return 1; }

    /* DOS header + stub */
    fwrite(dos_stub, 1, 256, out);

    /* PE header block */
    fwrite(pe_block, 1, 256, out);

    /* Pad to headers_size */
    int pad = headers_size - 512;
    if (pad > 0) {
        uint8_t *zeros = calloc(1, pad);
        fwrite(zeros, 1, pad, out);
        free(zeros);
    }

    /* .text section = ELF binary (PE loader will map this) */
    fwrite(elf_data, 1, elf_size, out);

    /* Pad to file alignment */
    int text_pad = code_size - elf_size;
    if (text_pad > 0) {
        uint8_t *zeros = calloc(1, text_pad);
        fwrite(zeros, 1, text_pad, out);
        free(zeros);
    }

    /* Append ELF marker + full ELF for shell script extraction */
    fprintf(out, "\n__ELF__\n");
    fwrite(elf_data, 1, elf_size, out);

    fclose(out);

    long total = headers_size + code_size + 9 + elf_size;
    printf("APE: %s (%ld bytes = %.1fKB)\n", out_path, total, total / 1024.0);
    printf("  PE loader: .text at RVA 0x1000 (%d bytes)\n", (int)elf_size);
    printf("  Shell: extracts ELF from __ELF__ marker\n");

    free(elf_data);
    return 0;
}
