#!/usr/bin/env python3
"""mkpolyglot.py — Transform ELF binary into MZ+ELF polyglot

Creates a binary that:
  - Starts with MZ (0x4D5A) — Windows PE loader recognizes it
  - Contains a PE header pointing to our code
  - The first bytes (MZ = dec ebp; pop rdx) are valid x86_64 instructions
  - Followed by a jmp to the real entry point (skipping PE headers)
  - On Linux: needs binfmt_misc registration OR ape-loader

Usage: python3 mkpolyglot.py <input.elf> <output.com> [icon.ico]
"""

import struct, sys, os

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <input.elf> <output.com> [icon.ico]")
        sys.exit(1)

    elf_path = sys.argv[1]
    out_path = sys.argv[2]
    ico_path = sys.argv[3] if len(sys.argv) > 3 else None

    with open(elf_path, 'rb') as f:
        elf = f.read()

    # Verify ELF
    assert elf[:4] == b'\x7fELF', "Not an ELF file"

    # Parse ELF entry point
    entry = struct.unpack('<Q', elf[24:32])[0]
    phoff = struct.unpack('<Q', elf[32:40])[0]
    print(f"ELF: {len(elf)} bytes, entry=0x{entry:x}")

    # Find .text LOAD segment (first executable)
    phnum = struct.unpack('<H', elf[56:58])[0]
    phsize = struct.unpack('<H', elf[54:56])[0]
    text_offset = 0
    text_vaddr = 0
    text_filesz = 0
    for i in range(phnum):
        ph = elf[phoff + i*phsize : phoff + (i+1)*phsize]
        p_type, p_flags = struct.unpack('<II', ph[:8])
        p_offset, p_vaddr, p_paddr, p_filesz, p_memsz = struct.unpack('<QQQQQ', ph[8:48])
        if p_type == 1 and (p_flags & 1):  # PT_LOAD + PF_X
            text_offset = p_offset
            text_vaddr = p_vaddr
            text_filesz = p_filesz
            break

    print(f"  .text: offset=0x{text_offset:x} vaddr=0x{text_vaddr:x} size=0x{text_filesz:x}")
    entry_file_offset = text_offset + (entry - text_vaddr)
    print(f"  entry file offset: 0x{entry_file_offset:x}")

    # Read icon if provided
    ico_data = b''
    if ico_path and os.path.exists(ico_path):
        with open(ico_path, 'rb') as f:
            ico_data = f.read()
        print(f"  icon: {len(ico_data)} bytes")

    # === Build polyglot ===
    #
    # Layout:
    # [0x000] MZ + jmp (valid x86_64: dec ebp; pop rdx; jmp rel32)
    # [0x004] DOS header padding
    # [0x03C] e_lfanew → PE header offset
    # [0x040..0x07F] More header / padding
    # [0x080] PE header (PE\0\0 + COFF + Optional + Sections)
    # [0x200] Original ELF data (PE .text section maps here)
    #
    # The trick: bytes 0x000-0x001 are 'MZ' which Windows needs.
    # On Linux, these bytes are NOT valid ELF magic, so the kernel
    # won't execute it directly. We need binfmt_misc or ape-loader.
    #
    # HOWEVER: we can make it work WITHOUT binfmt_misc by putting
    # a valid ELF header at the very start and making the MZ header
    # be part of the ELF padding. The problem: ELF magic is 7F 45 4C 46
    # and MZ magic is 4D 5A — they can't overlap.
    #
    # Practical solution: output has MZ first. On Linux, use:
    #   1) chmod +x pmash.com && ./pmash.com  (needs binfmt_misc)
    #   2) OR: ape-loader pmash.com           (Cosmopolitan's loader)
    #   3) OR: install APE binfmt_misc entry

    pe_offset = 0x80
    headers_size = 0x200  # aligned to 512
    file_align = 512
    sect_align = 4096

    # Round ELF to file alignment
    padded_elf = elf + b'\0' * (file_align - (len(elf) % file_align)) if len(elf) % file_align else elf

    # PE section maps the ELF's .text at its original virtual address
    # ELF .text is at vaddr text_vaddr (0x401000), image base is 0x400000
    # So code_rva = text_vaddr - image_base = 0x1000
    image_base = 0x400000
    code_rva = text_vaddr - image_base  # 0x1000
    # Entry RVA = entry vaddr - image_base
    entry_rva = entry - image_base  # 0x1f9b

    image_size = code_rva + len(padded_elf) + sect_align
    image_size = (image_size + sect_align - 1) & ~(sect_align - 1)

    out = bytearray(headers_size + len(padded_elf))

    # DOS header
    struct.pack_into('<H', out, 0, 0x5A4D)  # e_magic = MZ

    # jmp over headers (offset 2..5)
    # Short jump: EB xx (2 bytes) or near jump: E9 xx xx xx xx (5 bytes)
    # Jump from offset 2 to offset 0x200 = distance 0x1FE - 5 = 0x1F9
    # Actually this is inside the e_cblp field. Let's put the jump target carefully.
    # The MZ bytes 4D 5A decode as: dec ebp (4D, REX prefix ignored in 64-bit); pop rdx (5A)
    # Then we can put: jmp rel32 → E9 xx xx xx xx
    out[2] = 0xE9  # jmp rel32
    jmp_target = headers_size - 7  # relative to after the 5-byte jmp (offset 7)
    struct.pack_into('<i', out, 3, jmp_target)

    # e_lfanew at offset 0x3C
    struct.pack_into('<I', out, 0x3C, pe_offset)

    # PE header at pe_offset
    p = pe_offset
    struct.pack_into('<I', out, p, 0x00004550)  # PE\0\0
    p += 4
    struct.pack_into('<H', out, p, 0x8664)  # Machine: AMD64
    p += 2
    num_sections = 1
    struct.pack_into('<H', out, p, num_sections)
    p += 2
    p += 4 + 4 + 4  # timestamp, symtab, numsym
    opt_size = 112 + 0 * 8  # no data directories for minimal PE
    struct.pack_into('<H', out, p, opt_size)
    p += 2
    struct.pack_into('<H', out, p, 0x0022)  # characteristics
    p += 2

    # Optional header (PE32+)
    opt_start = p
    struct.pack_into('<H', out, p, 0x020B)  # PE32+
    p += 2
    p += 2  # linker version
    struct.pack_into('<I', out, p, len(padded_elf))  # code size
    p += 4
    p += 4 + 4  # init data, uninit data
    struct.pack_into('<I', out, p, entry_rva)  # entry point RVA
    p += 4
    struct.pack_into('<I', out, p, code_rva)  # base of code
    p += 4
    struct.pack_into('<Q', out, p, image_base)  # image base — match ELF vaddr!
    p += 8
    struct.pack_into('<I', out, p, sect_align)  # section alignment
    p += 4
    struct.pack_into('<I', out, p, file_align)  # file alignment
    p += 4
    struct.pack_into('<HH', out, p, 6, 0)  # OS version
    p += 4
    p += 4  # image version
    struct.pack_into('<HH', out, p, 6, 0)  # subsystem version
    p += 4
    p += 4  # win32 version
    struct.pack_into('<I', out, p, image_size)
    p += 4
    struct.pack_into('<I', out, p, headers_size)
    p += 4
    p += 4  # checksum
    struct.pack_into('<H', out, p, 3)  # subsystem: CONSOLE
    p += 2
    struct.pack_into('<H', out, p, 0x8160)  # dll characteristics
    p += 2
    struct.pack_into('<Q', out, p, 0x100000)  # stack reserve
    p += 8
    struct.pack_into('<Q', out, p, 0x1000)  # stack commit
    p += 8
    struct.pack_into('<Q', out, p, 0x100000)  # heap reserve
    p += 8
    struct.pack_into('<Q', out, p, 0x1000)  # heap commit
    p += 8
    p += 4  # loader flags
    struct.pack_into('<I', out, p, 0)  # num data dirs
    p += 4

    # Section table
    out[p:p+8] = b'.text\0\0\0'
    p += 8
    struct.pack_into('<I', out, p, len(padded_elf))  # virtual size
    p += 4
    struct.pack_into('<I', out, p, code_rva)  # virtual address
    p += 4
    struct.pack_into('<I', out, p, len(padded_elf))  # raw size
    p += 4
    struct.pack_into('<I', out, p, headers_size + text_offset)  # raw pointer to .text in polyglot
    p += 4
    p += 4 + 4 + 2 + 2  # relocs, linenums
    struct.pack_into('<I', out, p, 0x60000020)  # CODE|EXEC|READ

    # Copy ELF data at headers_size
    out[headers_size:headers_size + len(elf)] = elf

    # Write output
    with open(out_path, 'wb') as f:
        f.write(out)
    os.chmod(out_path, 0o755)

    print(f"\nOutput: {out_path} ({len(out)} bytes = {len(out)/1024:.1f}KB)")
    print(f"  MZ header: offset 0x000 (Windows PE loader)")
    print(f"  PE header: offset 0x{pe_offset:03x}")
    print(f"  Code:      offset 0x{headers_size:03x} ({len(elf)} bytes)")
    print(f"  Entry RVA: 0x{entry_rva:x}")
    print(f"  NOTE: On Linux, needs binfmt_misc for .com or use: ape-loader {out_path}")

if __name__ == '__main__':
    main()
