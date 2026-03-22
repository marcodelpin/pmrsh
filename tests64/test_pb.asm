;; test_pb.asm — Test protobuf varint encode/decode (x86_64)
bits 64
default rel

%include "vtable64.inc"
%include "linux64.inc"
%include "../common64/util.inc"
%include "../common64/protobuf.inc"

section .data
    t1 db "[pb] encode_varint(1) -> 0x01", 10, 0
    t2 db "[pb] encode_varint(300) -> 0xAC02", 10, 0
    t3 db "[pb] decode_varint(0x01) -> 1", 10, 0
    t4 db "[pb] decode_varint(0xAC02) -> 300", 10, 0
    pass db "  PASS", 10, 0
    fail db "  FAIL", 10, 0

section .bss
    buf resb 16

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

    ;; T1: encode_varint(1)
    lea     rdi, [t1]
    call    print
    lea     rdi, [buf]
    mov     rsi, 1
    call    pb_encode_varint
    cmp     eax, 1
    jne     .t1f
    cmp     byte [buf], 0x01
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
    lea     rdi, [buf]
    mov     rsi, 300
    call    pb_encode_varint
    cmp     eax, 2
    jne     .t2f
    cmp     byte [buf], 0xAC
    jne     .t2f
    cmp     byte [buf+1], 0x02
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
    mov     byte [buf], 0x01
    lea     rdi, [buf]
    call    pb_decode_varint
    cmp     eax, 1
    jne     .t3f
    lea     rdi, [pass]
    call    print
    jmp     .t4
.t3f:
    lea     rdi, [fail]
    call    print

.t4:
    lea     rdi, [t4]
    call    print
    mov     byte [buf], 0xAC
    mov     byte [buf+1], 0x02
    lea     rdi, [buf]
    call    pb_decode_varint
    cmp     eax, 300
    jne     .t4f
    lea     rdi, [pass]
    call    print
    jmp     .done
.t4f:
    lea     rdi, [fail]
    call    print

.done:
    xor     edi, edi
    call    [os_vtable.exit]
