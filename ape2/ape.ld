/* ape.ld — Linker script: page-aligned segments for PE polyglot compat */
OUTPUT_FORMAT("elf64-x86-64")
ENTRY(_start)

SECTIONS {
    . = 0x400000 + SIZEOF_HEADERS;

    . = ALIGN(0x1000);
    .text : {
        *(.text .text.* .gnu.linkonce.t.*)
        *(.plt .plt.*)
        *(.init) *(.fini)
    }

    . = ALIGN(0x1000);
    .rodata : {
        *(.rodata .rodata.* .gnu.linkonce.r.*)
        *(.rodata.str1.1 .rodata.str1.8 .rodata.str1.4)
        *(.rodata.cst4 .rodata.cst8 .rodata.cst16 .rodata.cst32)
        *(.data.rel.ro .data.rel.ro.*)
        *(.init_array .init_array.*)
        *(.fini_array .fini_array.*)
        *(.note .note.*)
    }

    . = ALIGN(0x1000);
    .data : {
        *(.data .data.* .gnu.linkonce.d.*)
        *(.got .got.*)
        *(.toc .toc.*)
    }
    .bss : {
        *(.bss .bss.* .gnu.linkonce.b.*)
        *(COMMON)
    }

    /DISCARD/ : {
        *(.comment)
        *(.eh_frame .eh_frame_hdr)
        *(.note.GNU-stack)
        *(.note.gnu.build-id)
        *(.note.gnu.property)
    }
}
