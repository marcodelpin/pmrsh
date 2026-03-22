;; =============================================================================
;; pmash-ape.asm — Actually Portable Executable prototype
;; Single binary that runs on Windows x64 + Linux x64
;; =============================================================================
;; Inspired by Cosmopolitan Libc's APE format.
;; The file is simultaneously:
;;   1. A valid Windows PE (MZ header → PE → .text)
;;   2. A valid shell script (MZ bytes start a variable assignment)
;;   3. Contains an embedded ELF that the shell script extracts and runs
;; =============================================================================

bits 64
org 0

;; =============================================================================
;; POLYGLOT HEADER — First 2 bytes = "MZ" (PE magic)
;; The shell sees: MZqFpD='...binary...' ; <bootstrap script>
;; Windows sees: MZ DOS header → PE header → execute
;; =============================================================================

header:
    ;; Bytes 0-1: MZ magic (PE) / start of shell variable assignment
    db 'M', 'Z'                    ; PE: e_magic = "MZ"
                                    ; Shell: M and Z are harmless

    ;; Bytes 2-7: Complete the shell variable name + open quote
    ;; These must also be valid (or harmless) x86-64 instructions
    db 'q'                          ; x86: (part of conditional jump encoding)
    db 'F'                          ;
    db 'p'                          ;
    db 'D'                          ;
    db '='                          ;
    db 27h                          ; single quote — opens the string

    ;; Bytes 8-59: DOS header fields (shell ignores — inside quoted string)
    ;; We fill with values that make the PE loader happy
    dw 0x0090                       ; e_cblp: bytes on last page
    dw 0x0003                       ; e_cp: pages in file
    dw 0x0000                       ; e_crlc: relocations
    dw 0x0004                       ; e_cparhdr: size of header in paragraphs
    dw 0x0000                       ; e_minalloc
    dw 0xFFFF                       ; e_maxalloc
    dw 0x0000                       ; e_ss
    dw 0x00B8                       ; e_sp
    dw 0x0000                       ; e_csum
    dw 0x0000                       ; e_ip
    dw 0x0000                       ; e_cs
    dw 0x0040                       ; e_lfarlc
    dw 0x0000                       ; e_ovno
    times 4 dw 0                    ; e_res[4]
    dw 0x0000                       ; e_oemid
    dw 0x0000                       ; e_oeminfo
    times 10 dw 0                   ; e_res2[10]
    dd pe_header                    ; e_lfanew: offset to PE header

;; =============================================================================
;; PE HEADER (at offset pointed to by e_lfanew)
;; =============================================================================
align 8
pe_header:
    db 'P', 'E', 0, 0              ; PE signature

    ;; COFF Header
    dw 0x8664                       ; Machine: AMD64
    dw 1                            ; NumberOfSections
    dd 0                            ; TimeDateStamp
    dd 0                            ; PointerToSymbolTable
    dd 0                            ; NumberOfSymbols
    dw opt_header_size              ; SizeOfOptionalHeader
    dw 0x0022                       ; Characteristics: EXECUTABLE | LARGE_ADDRESS_AWARE

    ;; Optional Header (PE32+)
opt_header:
    dw 0x020B                       ; Magic: PE32+ (64-bit)
    db 1                            ; MajorLinkerVersion
    db 0                            ; MinorLinkerVersion
    dd code_size                    ; SizeOfCode
    dd 0                            ; SizeOfInitializedData
    dd 0                            ; SizeOfUninitializedData
    dd win_entry - image_base_val   ; AddressOfEntryPoint (RVA)
    dd code_start - image_base_val  ; BaseOfCode (RVA)
    dq image_base_val               ; ImageBase
    dd 0x1000                       ; SectionAlignment
    dd 0x0200                       ; FileAlignment
    dw 6                            ; MajorOSVersion
    dw 0                            ; MinorOSVersion
    dw 0                            ; MajorImageVersion
    dw 0                            ; MinorImageVersion
    dw 6                            ; MajorSubsystemVersion
    dw 0                            ; MinorSubsystemVersion
    dd 0                            ; Win32VersionValue
    dd file_size                    ; SizeOfImage
    dd header_size                  ; SizeOfHeaders
    dd 0                            ; CheckSum
    dw 3                            ; Subsystem: CONSOLE
    dw 0x8160                       ; DllCharacteristics: NX | DYNAMIC_BASE | HIGH_ENTROPY_VA | TERMINAL_SERVER_AWARE
    dq 0x100000                     ; SizeOfStackReserve
    dq 0x1000                       ; SizeOfStackCommit
    dq 0x100000                     ; SizeOfHeapReserve
    dq 0x1000                       ; SizeOfHeapCommit
    dd 0                            ; LoaderFlags
    dd 16                           ; NumberOfRvaAndSizes

    ;; Data directories (16 entries, all zero for minimal PE)
    times 16 dq 0

opt_header_size equ $ - opt_header

;; Section header (.text)
section_header:
    db '.text', 0, 0, 0             ; Name
    dd code_size                    ; VirtualSize
    dd code_start - image_base_val  ; VirtualAddress (RVA)
    dd code_size                    ; SizeOfRawData
    dd code_start_file              ; PointerToRawData
    dd 0                            ; PointerToRelocations
    dd 0                            ; PointerToLinenumbers
    dw 0                            ; NumberOfRelocations
    dw 0                            ; NumberOfLinenumbers
    dd 0x60000020                   ; Characteristics: CODE | EXECUTE | READ

header_size equ $ - header

;; =============================================================================
;; SHELL SCRIPT BOOTSTRAP (embedded after PE headers, inside the quoted string)
;; The closing quote + script comes here
;; =============================================================================
align 16
shell_bootstrap:
    ;; Close the quoted string, then run bootstrap
    db 27h                          ; closing single quote
    db ' ', ';', ' '                ; shell: end of assignment
    ;; Now the actual shell script:
    db 'e=;o=$(uname -s);a=$(uname -m);'
    db 'case $o in Linux) '
    db 't=$(mktemp /tmp/pmash.XXXXXX);'
    db 'dd if="$0" bs=1 skip='
    ;; We'll fill in the ELF offset as ASCII digits
elf_offset_str:
    db '4096'                       ; placeholder — actual offset of embedded ELF
    db ' count='
elf_size_str:
    db '8192'                       ; placeholder — actual size of embedded ELF
    db ' of="$t" 2>/dev/null;'
    db 'chmod +x "$t";exec "$t" "$@";;'
    db '*) echo "pmash: unsupported OS: $o" >&2;exit 1;;'
    db 'esac', 10, 0

;; =============================================================================
;; PADDING to align code section
;; =============================================================================
times 512 - ($ - header) db 0
code_start_file equ $ - header

;; =============================================================================
;; WINDOWS CODE SECTION (x86-64)
;; =============================================================================
image_base_val equ 0x140000000
code_start equ image_base_val + code_start_file

win_entry:
    ;; Minimal Windows program: write "pmash 0.1.0" to stdout, exit
    ;; Uses raw syscalls would be fragile — use kernel32 imports instead
    ;; For prototype: use int 29h (fast console output, works in Windows console)

    ;; Actually, for a proper PE we need imports. For this prototype,
    ;; use the simplest possible approach: call NtWriteFile via syscall
    ;; This is fragile but works for demo.

    ;; Simple approach: use Windows syscall ABI
    ;; GetStdHandle(-11) → NtWriteFile
    ;; For prototype, just exit cleanly to prove PE works

    sub     rsp, 40                 ; shadow space

    ;; Call GetStdHandle(-11) — but we need IAT for this
    ;; For bare PE prototype, just exit with code 42 to prove it runs
    mov     ecx, 42                 ; exit code = 42 (proof of life)
    ;; ExitProcess would need import — use RtlExitUserProcess from ntdll
    ;; For absolute minimal: int 2Eh with NtTerminateProcess
    xor     edx, edx
    mov     r10, rcx
    mov     eax, 0x2C               ; NtTerminateProcess syscall number (Win10+)
    syscall

    ;; Fallback: infinite loop (should never reach)
    jmp     $

win_version_str:
    db 'pmash 0.1.0 (ape/windows)', 13, 10, 0

code_size equ $ - win_entry

;; =============================================================================
;; PADDING to page boundary for embedded ELF
;; =============================================================================
times 4096 - ($ - header) db 0

;; =============================================================================
;; EMBEDDED ELF (Linux x86-64) — starts at offset 4096
;; This is the self-contained Linux binary that the shell script extracts
;; =============================================================================
elf_start:

;; ELF Header
    db 0x7F, 'E', 'L', 'F'         ; e_ident: magic
    db 2                            ; EI_CLASS: 64-bit
    db 1                            ; EI_DATA: little-endian
    db 1                            ; EI_VERSION: current
    db 0                            ; EI_OSABI: SYSV
    dq 0                            ; EI_ABIVERSION + padding
    dw 2                            ; e_type: ET_EXEC
    dw 0x3E                         ; e_machine: x86-64
    dd 1                            ; e_version
    dq 0x400078                     ; e_entry: entry point (vaddr)
    dq 0x40                         ; e_phoff: program header offset
    dq 0                            ; e_shoff: no section headers
    dd 0                            ; e_flags
    dw 64                           ; e_ehsize
    dw 56                           ; e_phentsize
    dw 1                            ; e_phnum
    dw 0                            ; e_shentsize
    dw 0                            ; e_shnum
    dw 0                            ; e_shstrndx

;; Program Header (LOAD)
    dd 1                            ; p_type: PT_LOAD
    dd 5                            ; p_flags: PF_R | PF_X
    dq 0                            ; p_offset
    dq 0x400000                     ; p_vaddr
    dq 0x400000                     ; p_paddr
    dq elf_file_size                ; p_filesz
    dq elf_file_size                ; p_memsz
    dq 0x1000                       ; p_align

;; Linux entry point (at vaddr 0x400078)
linux_entry:
    ;; write(1, msg, len)
    mov     edi, 1                  ; fd = stdout
    lea     rsi, [rel linux_msg]    ; buf
    mov     edx, linux_msg_len      ; len
    mov     eax, 1                  ; SYS_WRITE
    syscall

    ;; exit(0)
    xor     edi, edi
    mov     eax, 60                 ; SYS_EXIT
    syscall

linux_msg:
    db 'pmash 0.1.0 (ape/linux)', 10
linux_msg_len equ $ - linux_msg

elf_file_size equ $ - elf_start

;; =============================================================================
;; FILE SIZE
;; =============================================================================
file_size equ $ - header
