;; test_pb.asm — Test protobuf varint encode/decode
bits 32

%include "vtable.inc"
%include "linux.inc"
%include "../common/util.inc"
%include "../common/protobuf.inc"

section .data
    t1 db "[pb] varint encode 0 → 1 byte", 10, 0
    t2 db "[pb] varint encode 128 → 2 bytes (0x80 0x01)", 10, 0
    t3 db "[pb] varint encode+decode round-trip 12345", 10, 0
    t4 db "[pb] write_string field 1 'hello'", 10, 0
    pass db "  PASS", 10, 0
    fail db "  FAIL", 10, 0
    hello db "hello", 0

section .bss
    buf resb 256

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

    ;; T1: encode 0
    mov     esi, t1
    call    print
    lea     edi, [buf]
    xor     eax, eax
    call    pb_encode_varint
    cmp     ecx, 1
    jne     .f1
    cmp     byte [buf], 0
    jne     .f1
    mov     esi, pass
    call    print
    jmp     .t2
.f1:
    mov     esi, fail
    call    print

.t2:
    mov     esi, t2
    call    print
    lea     edi, [buf]
    mov     eax, 128
    call    pb_encode_varint
    cmp     ecx, 2
    jne     .f2
    cmp     byte [buf], 0x80
    jne     .f2
    cmp     byte [buf+1], 0x01
    jne     .f2
    mov     esi, pass
    call    print
    jmp     .t3
.f2:
    mov     esi, fail
    call    print

.t3:
    mov     esi, t3
    call    print
    lea     edi, [buf]
    mov     eax, 12345
    call    pb_encode_varint
    ;; Decode back
    mov     esi, buf
    call    pb_decode_varint
    cmp     eax, 12345
    jne     .f3
    mov     esi, pass
    call    print
    jmp     .t4
.f3:
    mov     esi, fail
    call    print

.t4:
    mov     esi, t4
    call    print
    lea     edi, [buf]
    mov     ebx, 1              ; field number
    mov     esi, hello
    mov     ecx, 5
    call    pb_write_string
    ;; Should be: tag(0x0A) + len(5) + "hello" = 7 bytes
    cmp     eax, 7
    jne     .f4
    cmp     byte [buf], 0x0A
    jne     .f4
    cmp     byte [buf+1], 5
    jne     .f4
    cmp     byte [buf+2], 'h'
    jne     .f4
    mov     esi, pass
    call    print
    jmp     .done
.f4:
    mov     esi, fail
    call    print

.done:
    push    0
    call    [os_vtable.exit]
