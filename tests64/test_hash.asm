;; test_hash.asm — Test Adler32 with known vectors (x86_64)
bits 64
default rel

%include "vtable64.inc"
%include "linux64.inc"
%include "../common64/util.inc"
%include "../common64/hash.inc"

section .data
    t1 db "[hash] adler32 empty -> 1", 10, 0
    t2 db "[hash] adler32 'abc' -> 0x024D0127", 10, 0
    t3 db "[hash] adler32 'Wikipedia' -> 0x11E60398", 10, 0
    pass db "  PASS", 10, 0
    fail db "  FAIL", 10, 0
    abc db "abc", 0
    wiki db "Wikipedia", 0

section .text
global _start

print:
    ;; rdi = string
    push    rbx
    mov     rbx, rdi
    call    pm_strlen
    mov     rdx, rax
    mov     rsi, rbx
    mov     edi, 1
    call    [os_vtable.write]
    pop     rbx
    ret

_start:
    call    detect_os
    call    patch_vtable

    ;; T1: empty → 1
    lea     rdi, [t1]
    call    print
    xor     edi, edi               ; data = NULL
    xor     esi, esi               ; len = 0
    call    adler32
    cmp     eax, 1
    je      .t1p
    lea     rdi, [fail]
    call    print
    jmp     .t2
.t1p:
    lea     rdi, [pass]
    call    print

.t2:
    lea     rdi, [t2]
    call    print
    lea     rdi, [abc]
    mov     esi, 3
    call    adler32
    cmp     eax, 0x024D0127
    je      .t2p
    lea     rdi, [fail]
    call    print
    jmp     .t3
.t2p:
    lea     rdi, [pass]
    call    print

.t3:
    lea     rdi, [t3]
    call    print
    lea     rdi, [wiki]
    mov     esi, 9
    call    adler32
    cmp     eax, 0x11E60398
    je      .t3p
    lea     rdi, [fail]
    call    print
    jmp     .done
.t3p:
    lea     rdi, [pass]
    call    print

.done:
    xor     edi, edi
    call    [os_vtable.exit]
