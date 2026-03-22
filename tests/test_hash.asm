;; test_hash.asm — Test Adler32 with known vectors
bits 32

%include "vtable.inc"
%include "linux.inc"
%include "../common/util.inc"
%include "../common/hash.inc"

section .data
    t1 db "[hash] adler32 empty → 1", 10, 0
    t2 db "[hash] adler32 'abc' → 0x024D0127", 10, 0
    t3 db "[hash] adler32 'Wikipedia' → 0x11E60398", 10, 0
    pass db "  PASS", 10, 0
    fail db "  FAIL", 10, 0
    abc db "abc", 0
    wiki db "Wikipedia", 0

section .text
global _start

print:
    call    pm_strlen
    push    eax
    push    esi
    push    1
    call    [os_vtable.write]
    add     esp, 12
    ret

_start:
    call    detect_os
    call    patch_vtable

    ;; T1: empty → 1
    mov     esi, t1
    call    print
    mov     esi, 0
    xor     ecx, ecx
    call    adler32
    cmp     eax, 1
    je      .t1p
    mov     esi, fail
    call    print
    jmp     .t2
.t1p:
    mov     esi, pass
    call    print

.t2:
    mov     esi, t2
    call    print
    mov     esi, abc
    mov     ecx, 3
    call    adler32
    cmp     eax, 0x024D0127
    je      .t2p
    mov     esi, fail
    call    print
    jmp     .t3
.t2p:
    mov     esi, pass
    call    print

.t3:
    mov     esi, t3
    call    print
    mov     esi, wiki
    mov     ecx, 9
    call    adler32
    cmp     eax, 0x11E60398
    je      .t3p
    mov     esi, fail
    call    print
    jmp     .done
.t3p:
    mov     esi, pass
    call    print

.done:
    push    0
    call    [os_vtable.exit]
