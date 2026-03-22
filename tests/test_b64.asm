;; test_b64.asm — Test base64 encode/decode (RFC 4648)
bits 32

%include "vtable.inc"
%include "linux.inc"
%include "../common/util.inc"
%include "../common/base64.inc"

section .data
    t1 db "[b64] encode 'foo' → 'Zm9v'", 10, 0
    t2 db "[b64] encode 'f' → 'Zg=='", 10, 0
    t3 db "[b64] decode round-trip 'Hello'", 10, 0
    pass db "  PASS", 10, 0
    fail db "  FAIL", 10, 0
    foo db "foo", 0
    f_str db "f", 0
    hello db "Hello", 0
    exp_foo db "Zm9v", 0
    exp_f db "Zg==", 0

section .bss
    outbuf resb 256
    decbuf resb 256

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

strcmp_local: ; esi=a, edi=b → eax 0=match
    xor     ecx, ecx
.l:
    mov     al, [esi+ecx]
    cmp     al, [edi+ecx]
    jne     .ne
    test    al, al
    jz      .eq
    inc     ecx
    jmp     .l
.eq:
    xor     eax, eax
    ret
.ne:
    mov     eax, 1
    ret

_start:
    call    detect_os
    call    patch_vtable

    ;; T1: encode "foo" → "Zm9v"
    mov     esi, t1
    call    print
    mov     esi, foo
    mov     ecx, 3
    lea     edi, [outbuf]
    call    b64_encode
    mov     byte [outbuf+eax], 0
    mov     esi, outbuf
    lea     edi, [exp_foo]
    call    strcmp_local
    test    eax, eax
    jnz     .f1
    mov     esi, pass
    call    print
    jmp     .t2
.f1:
    mov     esi, fail
    call    print

.t2:
    mov     esi, t2
    call    print
    mov     esi, f_str
    mov     ecx, 1
    lea     edi, [outbuf]
    call    b64_encode
    mov     byte [outbuf+eax], 0
    mov     esi, outbuf
    lea     edi, [exp_f]
    call    strcmp_local
    test    eax, eax
    jnz     .f2
    mov     esi, pass
    call    print
    jmp     .t3
.f2:
    mov     esi, fail
    call    print

.t3:
    ;; Round-trip: encode "Hello" then decode, compare
    mov     esi, t3
    call    print
    mov     esi, hello
    mov     ecx, 5
    lea     edi, [outbuf]
    call    b64_encode
    mov     byte [outbuf+eax], 0
    ;; Decode
    mov     esi, outbuf
    lea     edi, [decbuf]
    mov     ecx, 256
    call    b64_decode
    mov     byte [decbuf+eax], 0
    ;; Compare
    mov     esi, decbuf
    lea     edi, [hello]
    call    strcmp_local
    test    eax, eax
    jnz     .f3
    mov     esi, pass
    call    print
    jmp     .done
.f3:
    mov     esi, fail
    call    print

.done:
    push    0
    call    [os_vtable.exit]
