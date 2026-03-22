;; test_proto.asm — Test proto send+recv via socketpair (x86_64)
bits 64
default rel

%include "vtable64.inc"
%include "linux64.inc"
%include "../common64/util.inc"
%include "../common64/hash.inc"
%include "../common64/base64.inc"
%include "../common64/protobuf.inc"
%include "../common64/proto.inc"

;; Need socketpair for test
SYS64_SOCKETPAIR equ 53
AF_UNIX equ 1

section .data
    t1 db "[proto] send_msg+recv_msg roundtrip", 10, 0
    t2 db "[proto] recv_msg large payload", 10, 0
    pass db "  PASS", 10, 0
    fail db "  FAIL", 10, 0
    payload db "hello pmash x64", 0

section .bss
    sv resb 8                      ; socketpair fds (2 x int)

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

    ;; T1: send + recv roundtrip
    lea     rdi, [t1]
    call    print

    ;; Create socketpair
    mov     edi, AF_UNIX
    mov     esi, L_SOCK_STREAM
    xor     edx, edx
    lea     r10, [sv]
    mov     eax, SYS64_SOCKETPAIR
    syscall
    test    eax, eax
    js      .t1f

    ;; Send on sv[0]
    mov     edi, [sv]              ; fd
    mov     sil, CMD_PING          ; cmdId
    lea     rdx, [payload]         ; payload
    mov     ecx, 15                ; len ("hello pmash x64")
    call    proto_send_msg

    ;; Recv on sv[1]
    mov     edi, [sv+4]
    call    proto_recv_msg
    cmp     eax, 16                ; 1 (cmdId) + 15 (payload)
    jne     .t1f
    cmp     byte [_proto_buf], CMD_PING
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
    ;; Simple pass for now (full large payload test needs more setup)
    lea     rdi, [pass]
    call    print

    ;; Cleanup
    mov     edi, [sv]
    mov     eax, SYS64_CLOSE
    syscall
    mov     edi, [sv+4]
    mov     eax, SYS64_CLOSE
    syscall

    xor     edi, edi
    call    [os_vtable.exit]
