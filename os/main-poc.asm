;; =============================================================================
;; main-poc.asm — Proof of concept: vtable-based OS abstraction
;; Compiles with NASM for Linux ELF32. Demonstrates the vtable pattern.
;; =============================================================================
;; Build: nasm -f elf32 -Ios/ main-poc.asm -o main-poc.o && ld -m elf_i386 -o pmash-poc main-poc.o
;; Run:   ./pmash-poc
;; =============================================================================

bits 32

%include "vtable.inc"
%include "linux.inc"

section .data
    hello   db "pmash 0.1.0 — vtable POC", 10, 0
    hello_l equ 25
    cmd     db "uname -a", 0
    exec_hdr db "exec output: ", 0
    exec_hdr_l equ 14
    newline db 10, 0

section .bss
    outbuf  resb 4096

section .text
    global _start

_start:
    ;; 1. Detect OS
    call    detect_os

    ;; 2. Patch vtable with OS-specific implementations
    call    patch_vtable

    ;; 3. Use vtable calls — this code is 100% OS-agnostic

    ;; Write version string to stdout (fd=1)
    push    hello_l
    push    hello
    push    1
    call    [os_vtable.write]
    add     esp, 12

    ;; Execute "uname -a" and capture output
    push    4096
    push    outbuf
    push    cmd
    call    [os_vtable.exec]
    add     esp, 12
    mov     ebx, eax                ; save output length

    ;; Print "exec output: "
    push    exec_hdr_l
    push    exec_hdr
    push    1
    call    [os_vtable.write]
    add     esp, 12

    ;; Print exec output
    test    ebx, ebx
    jle     .skip_output
    push    ebx
    push    outbuf
    push    1
    call    [os_vtable.write]
    add     esp, 12
.skip_output:

    ;; Print newline
    push    1
    push    newline
    push    1
    call    [os_vtable.write]
    add     esp, 12

    ;; Exit cleanly
    push    0
    call    [os_vtable.exit]
