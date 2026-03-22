;; test_b64.asm — Test Base64 RFC 4648 vectors (x86_64)
bits 64
default rel

%include "vtable64.inc"
%include "linux64.inc"
%include "../common64/util.inc"
%include "../common64/base64.inc"

section .data
    t1 db "[b64] encode('Man') -> 'TWFu'", 10, 0
    t2 db "[b64] encode('Ma') -> 'TWE='", 10, 0
    t3 db "[b64] encode('M') -> 'TQ=='", 10, 0
    pass db "  PASS", 10, 0
    fail db "  FAIL", 10, 0
    in1 db "Man", 0
    ex1 db "TWFu", 0
    in2 db "Ma", 0
    ex2 db "TWE=", 0
    in3 db "M", 0
    ex3 db "TQ==", 0

section .bss
    outbuf resb 64

section .text
global _start

print:
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

    ;; T1: encode("Man") → "TWFu"
    lea     rdi, [t1]
    call    print
    lea     rdi, [in1]
    mov     esi, 3
    lea     rdx, [outbuf]
    call    b64_encode
    cmp     eax, 4
    jne     .t1f
    cmp     dword [outbuf], 'TWFu'
    jne     .t1f
    lea     rdi, [pass]
    call    print
    jmp     .t2
.t1f:
    lea     rdi, [fail]
    call    print

.t2:
    lea     rdi, [t2]
    call    print
    lea     rdi, [in2]
    mov     esi, 2
    lea     rdx, [outbuf]
    call    b64_encode
    cmp     eax, 4
    jne     .t2f
    cmp     dword [outbuf], 'TWE='
    jne     .t2f
    lea     rdi, [pass]
    call    print
    jmp     .t3
.t2f:
    lea     rdi, [fail]
    call    print

.t3:
    lea     rdi, [t3]
    call    print
    lea     rdi, [in3]
    mov     esi, 1
    lea     rdx, [outbuf]
    call    b64_encode
    cmp     eax, 4
    jne     .t3f
    cmp     dword [outbuf], 'TQ=='
    jne     .t3f
    lea     rdi, [pass]
    call    print
    jmp     .done
.t3f:
    lea     rdi, [fail]
    call    print

.done:
    xor     edi, edi
    call    [os_vtable.exit]
