#!/usr/bin/env python3
"""mkpolyglot.py — ELF → MZ/PE+ELF polyglot (all segments mapped)

Maps every ELF LOAD segment as a PE section so Windows PE loader
creates the same memory layout as the Linux ELF loader.

Usage: python3 mkpolyglot.py <input.elf> <output.com>
"""

import struct, sys, os

def align(x, a):
    return (x + a - 1) & ~(a - 1)

def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <input.elf> <output.com>")
        sys.exit(1)

    with open(sys.argv[1], 'rb') as f:
        elf = bytearray(f.read())

    assert elf[:4] == b'\x7fELF', "Not ELF"

    entry = struct.unpack('<Q', elf[24:32])[0]
    phoff = struct.unpack('<Q', elf[32:40])[0]
    phnum = struct.unpack('<H', elf[56:58])[0]
    phsize = struct.unpack('<H', elf[54:56])[0]

    # Find entry_pe symbol for PE entry point (different from ELF _start)
    # Use nm on the unstripped binary, or pass as argument
    pe_entry = entry  # default: same as ELF entry
    import subprocess
    try:
        nm_out = subprocess.check_output(['nm', sys.argv[1]], stderr=subprocess.DEVNULL).decode()
        for line in nm_out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[2] == 'entry_pe':
                pe_entry = int(parts[0], 16)
                print(f"  entry_pe symbol at 0x{pe_entry:x}")
                break
    except:
        pass

    # Parse ALL LOAD segments
    segments = []
    for i in range(phnum):
        ph = elf[phoff + i*phsize : phoff + (i+1)*phsize]
        p_type = struct.unpack('<I', ph[:4])[0]
        p_flags = struct.unpack('<I', ph[4:8])[0]
        p_offset, p_vaddr, p_paddr, p_filesz, p_memsz = struct.unpack('<QQQQQ', ph[8:48])
        p_align = struct.unpack('<Q', ph[48:56])[0]
        if p_type == 1:  # PT_LOAD
            # PE section characteristics from ELF flags
            chars = 0x40000000  # IMAGE_SCN_MEM_READ
            name = ".data"
            if p_flags & 1:  # PF_X
                chars |= 0x20000020  # IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE
                name = ".text"
            if p_flags & 2:  # PF_W
                chars |= 0x80000000 | 0x00000040  # MEM_WRITE | INITIALIZED_DATA
                name = ".data"
            elif not (p_flags & 1):
                chars |= 0x00000040  # INITIALIZED_DATA
                name = ".rdata"

            segments.append({
                'name': name,
                'vaddr': p_vaddr,
                'memsz': p_memsz,
                'offset': p_offset,
                'filesz': p_filesz,
                'chars': chars,
            })
            print(f"  LOAD: vaddr=0x{p_vaddr:x} filesz=0x{p_filesz:x} memsz=0x{p_memsz:x} flags={p_flags} → {name}")

    if not segments:
        print("No LOAD segments!"); sys.exit(1)

    # Skip first LOAD if it's at image base with only headers (RVA=0 conflicts with PE headers)
    image_base = segments[0]['vaddr'] & ~0xFFF
    if segments[0]['vaddr'] == image_base and segments[0]['filesz'] < 0x1000:
        print(f"  Skipping first LOAD (ELF headers at base, RVA=0)")
        segments = segments[1:]
    entry_rva = pe_entry - image_base  # PE uses entry_pe, not ELF _start
    print(f"\nELF: {len(elf)} bytes, entry=0x{entry:x}, pe_entry=0x{pe_entry:x}")
    print(f"  image_base=0x{image_base:x}, PE entry_rva=0x{entry_rva:x}")
    print(f"  {len(segments)} LOAD segments")

    FILE_ALIGN = 512
    SECT_ALIGN = 4096

    # Add .idata section for imports (forces kernel32.dll loading)
    # We need 1 extra section for the import directory
    num_pe_sections = len(segments) + 1  # +1 for .idata

    # PE header size: DOS(64) + pad + PE(24) + OptionalPE32+(112+16*2) + sections(40*N)
    pe_offset = 0x80
    num_data_dirs = 2  # [0]=export(unused), [1]=import
    opt_size = 112 + num_data_dirs * 8
    sect_table_offset = pe_offset + 4 + 20 + opt_size
    headers_end = sect_table_offset + 40 * num_pe_sections
    headers_size = align(headers_end, FILE_ALIGN)

    # Calculate total image size
    max_rva = 0
    for seg in segments:
        rva = seg['vaddr'] - image_base
        end = rva + align(seg['memsz'], SECT_ALIGN)
        if end > max_rva:
            max_rva = end
    image_size = align(max_rva, SECT_ALIGN)

    # Calculate file layout: each segment at its original ELF offset + headers_size
    # BUT PE requires sections to be in order and file-aligned.
    # Simplest: put the entire ELF file after headers, map each segment from it.

    elf_file_offset = headers_size  # entire ELF starts here
    total_file_size = elf_file_offset + len(elf)
    total_file_size = align(total_file_size, FILE_ALIGN)

    out = bytearray(total_file_size)

    # === DOS header ===
    struct.pack_into('<H', out, 0, 0x5A4D)  # MZ
    out[2] = 0xE9  # jmp rel32
    # Jump target: skip to where the ELF entry point code lives
    # entry is at file offset = elf_file_offset + (entry - segments[0].vaddr + segments[0].offset)
    # But simpler: jump to elf_file_offset which is the ELF header, won't help.
    # Actually on Linux this file won't be executed directly (not ELF at offset 0).
    # The jmp is for DOS compatibility only. Not needed for our use case.
    jmp_target = elf_file_offset - 7  # relative to offset 7 (after 5-byte jmp + 2-byte MZ)
    struct.pack_into('<i', out, 3, jmp_target)
    struct.pack_into('<I', out, 0x3C, pe_offset)  # e_lfanew

    # === PE header ===
    p = pe_offset
    struct.pack_into('<I', out, p, 0x00004550); p += 4  # PE\0\0
    struct.pack_into('<H', out, p, 0x8664); p += 2      # AMD64
    struct.pack_into('<H', out, p, len(segments)); p += 2  # num sections
    p += 4 + 4 + 4  # timestamp, symtab, numsym
    struct.pack_into('<H', out, p, opt_size); p += 2     # optional header size
    struct.pack_into('<H', out, p, 0x0022); p += 2       # characteristics

    # === Optional header (PE32+) ===
    struct.pack_into('<H', out, p, 0x020B); p += 2       # PE32+
    p += 2  # linker version
    code_size = sum(s['filesz'] for s in segments if s['chars'] & 0x20)
    struct.pack_into('<I', out, p, code_size); p += 4    # code size
    data_size = sum(s['filesz'] for s in segments if not (s['chars'] & 0x20))
    struct.pack_into('<I', out, p, data_size); p += 4    # initialized data
    bss_size = sum(s['memsz'] - s['filesz'] for s in segments)
    struct.pack_into('<I', out, p, bss_size); p += 4     # uninitialized data
    struct.pack_into('<I', out, p, entry_rva); p += 4    # entry point RVA
    code_rva = min(s['vaddr'] - image_base for s in segments if s['chars'] & 0x20) if code_size else 0
    struct.pack_into('<I', out, p, code_rva); p += 4     # base of code
    struct.pack_into('<Q', out, p, image_base); p += 8   # image base
    struct.pack_into('<I', out, p, SECT_ALIGN); p += 4   # section alignment
    struct.pack_into('<I', out, p, FILE_ALIGN); p += 4   # file alignment
    struct.pack_into('<HH', out, p, 6, 0); p += 4        # OS version
    p += 4  # image version
    struct.pack_into('<HH', out, p, 6, 0); p += 4        # subsystem version
    p += 4  # win32 version
    struct.pack_into('<I', out, p, image_size); p += 4    # image size
    struct.pack_into('<I', out, p, headers_size); p += 4  # headers size
    p += 4  # checksum
    struct.pack_into('<H', out, p, 3); p += 2             # CONSOLE
    struct.pack_into('<H', out, p, 0x8160); p += 2        # DLL characteristics
    struct.pack_into('<Q', out, p, 0x100000); p += 8      # stack reserve
    struct.pack_into('<Q', out, p, 0x1000); p += 8        # stack commit
    struct.pack_into('<Q', out, p, 0x100000); p += 8      # heap reserve
    struct.pack_into('<Q', out, p, 0x1000); p += 8        # heap commit
    p += 4  # loader flags
    struct.pack_into('<I', out, p, num_data_dirs); p += 4  # num data dirs
    # Data directory [0]: export (unused)
    p += 8
    # Data directory [1]: import — will be filled after we know idata RVA
    import_dd_offset = p
    p += 8  # placeholder, filled later

    # === Section table ===
    names_used = {}
    for seg in segments:
        rva = seg['vaddr'] - image_base
        raw_ptr = elf_file_offset + seg['offset']
        raw_size = align(seg['filesz'], FILE_ALIGN)

        # Unique section name
        name = seg['name']
        if name in names_used:
            names_used[name] += 1
            name = name[:5] + str(names_used[name])
        else:
            names_used[name] = 0

        out[p:p+8] = (name + '\0' * 8)[:8].encode()
        p += 8
        struct.pack_into('<I', out, p, seg['memsz']); p += 4   # virtual size
        struct.pack_into('<I', out, p, rva); p += 4             # virtual address
        struct.pack_into('<I', out, p, raw_size); p += 4        # raw size
        struct.pack_into('<I', out, p, raw_ptr); p += 4         # raw pointer
        p += 4 + 4 + 2 + 2  # relocs, linenums
        struct.pack_into('<I', out, p, seg['chars']); p += 4

        print(f"  PE section '{name}': RVA=0x{rva:x} raw=0x{raw_ptr:x} size=0x{seg['filesz']:x} mem=0x{seg['memsz']:x}")

    # === .idata section (import directory) ===
    # Place after last data segment
    last_seg = segments[-1]
    idata_rva = align(last_seg['vaddr'] - image_base + last_seg['memsz'], SECT_ALIGN)
    idata_file = elf_file_offset + len(elf)
    idata_file = align(idata_file, FILE_ALIGN)

    # Build import directory for kernel32.dll
    # Structure: IMAGE_IMPORT_DESCRIPTOR (20 bytes) + null terminator (20 bytes)
    # + ILT (8 bytes per entry + 8 null) + hint/name + DLL name
    idata = bytearray(256)
    id_off = 0

    # Hint/Name for "ExitProcess" at offset 128
    hint_off = 128
    struct.pack_into('<H', idata, hint_off, 0)  # hint
    idata[hint_off+2:hint_off+2+11] = b'ExitProcess'

    # DLL name "kernel32.dll" at offset 160
    dll_name_off = 160
    idata[dll_name_off:dll_name_off+12] = b'kernel32.dll'

    # ILT (Import Lookup Table) at offset 64
    ilt_off = 64
    struct.pack_into('<Q', idata, ilt_off, idata_rva + hint_off)  # RVA to hint/name
    struct.pack_into('<Q', idata, ilt_off + 8, 0)  # null terminator

    # IAT (Import Address Table) at offset 96 — same as ILT for simplicity
    iat_off = 96
    struct.pack_into('<Q', idata, iat_off, idata_rva + hint_off)
    struct.pack_into('<Q', idata, iat_off + 8, 0)

    # IMAGE_IMPORT_DESCRIPTOR at offset 0
    struct.pack_into('<I', idata, 0, idata_rva + ilt_off)       # OriginalFirstThunk (ILT)
    struct.pack_into('<I', idata, 4, 0)                          # TimeDateStamp
    struct.pack_into('<I', idata, 8, 0)                          # ForwarderChain
    struct.pack_into('<I', idata, 12, idata_rva + dll_name_off)  # Name RVA
    struct.pack_into('<I', idata, 16, idata_rva + iat_off)       # FirstThunk (IAT)
    # Null terminator descriptor
    idata[20:40] = b'\0' * 20

    idata_size = 192  # used bytes

    # Fill import data directory in optional header
    struct.pack_into('<I', out, import_dd_offset, idata_rva)
    struct.pack_into('<I', out, import_dd_offset + 4, idata_size)

    # Add .idata section entry
    out[p:p+8] = b'.idata\0\0'
    p += 8
    struct.pack_into('<I', out, p, idata_size); p += 4   # virtual size
    struct.pack_into('<I', out, p, idata_rva); p += 4    # virtual address
    struct.pack_into('<I', out, p, align(idata_size, FILE_ALIGN)); p += 4  # raw size
    struct.pack_into('<I', out, p, idata_file); p += 4   # raw pointer
    p += 4 + 4 + 2 + 2  # relocs, linenums
    struct.pack_into('<I', out, p, 0xC0000040)  # INITIALIZED_DATA|MEM_READ|MEM_WRITE
    p += 4
    print(f"  PE section '.idata': RVA=0x{idata_rva:x} raw=0x{idata_file:x} size=0x{idata_size:x}")

    # Update image size to include .idata
    new_image_size = align(idata_rva + idata_size, SECT_ALIGN)
    if new_image_size > image_size:
        image_size = new_image_size
        # Re-write image_size in optional header (it's at a known offset)
        # image_size is at opt header + 56
        opt_image_size_offset = pe_offset + 4 + 20 + 56
        struct.pack_into('<I', out, opt_image_size_offset, image_size)

    # Extend output to include .idata
    total_file_size = idata_file + align(idata_size, FILE_ALIGN)
    if len(out) < total_file_size:
        out.extend(b'\0' * (total_file_size - len(out)))
    out[idata_file:idata_file + len(idata)] = idata

    # === Copy ELF data ===
    out[elf_file_offset:elf_file_offset + len(elf)] = elf

    with open(sys.argv[2], 'wb') as f:
        f.write(out)
    os.chmod(sys.argv[2], 0o755)

    print(f"\nOutput: {sys.argv[2]} ({len(out)} bytes = {len(out)/1024:.1f}KB)")
    print(f"  MZ+PE at 0x000, ELF at 0x{elf_file_offset:x}")
    print(f"  {len(segments)} sections mapped, entry RVA=0x{entry_rva:x}")

if __name__ == '__main__':
    main()
