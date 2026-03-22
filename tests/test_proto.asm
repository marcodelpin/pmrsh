;; test_proto.asm — Test proto_send_msg/proto_recv_msg via loopback
;; Regression: edx was clobbered by send_all, causing partial messages
;; Build: nasm -f elf32 -Ios/ -Icommon/ test_proto.asm && ld -m elf_i386 -o test_proto test_proto.o
bits 32

%include "vtable.inc"
%include "linux.inc"
%include "../common/util.inc"
%include "../common/proto.inc"

section .data
    t1_name db "[proto] send+recv 32-byte message", 10, 0
    t2_name db "[proto] send+recv 1-byte message", 10, 0
    pass_str db "  PASS", 10, 0
    fail_str db "  FAIL", 10, 0
    test_data db "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"  ; 32 bytes
    test_1b   db 0x42                                ; 1 byte

section .bss
    sock_pair resd 2            ; socketpair fds
    recv_buf  resb 256

section .text
global _start

;; socketpair(AF_UNIX, SOCK_STREAM, 0, sv) via socketcall
;; subcall 8 = SYS_SOCKETPAIR
do_socketpair:
    push    ebx
    sub     esp, 16
    mov     dword [esp], 1      ; AF_UNIX
    mov     dword [esp+4], 1    ; SOCK_STREAM
    mov     dword [esp+8], 0    ; protocol
    mov     dword [esp+12], sock_pair  ; ptr to fds
    mov     eax, 102            ; SYS_SOCKETCALL
    mov     ebx, 8              ; SYS_SOCKETPAIR
    mov     ecx, esp
    int     0x80
    add     esp, 16
    pop     ebx
    ret

print:  ; esi = string
    call    pm_strlen
    push    eax
    push    esi
    push    1
    call    [os_vtable.write]
    add     esp, 12
    ret

print_result: ; eax = 0=pass
    test    eax, eax
    jnz     .fail
    mov     esi, pass_str
    call    print
    ret
.fail:
    mov     esi, fail_str
    call    print
    ret

_start:
    call    detect_os
    call    patch_vtable

    ;; Create socketpair for loopback testing
    call    do_socketpair
    test    eax, eax
    js      .bail

    ;; T1: send 32-byte message, recv and verify
    mov     esi, t1_name
    call    print

    ;; Send CMD_EXEC (0x10) + 32 bytes payload via sock_pair[0]
    push    32
    push    test_data
    push    byte 0x10           ; cmdId
    push    dword [sock_pair]   ; fd
    call    proto_send_msg
    add     esp, 16
    test    eax, eax
    jnz     .t1_fail

    ;; Recv on sock_pair[1]
    push    dword [sock_pair+4]
    call    proto_recv_msg
    add     esp, 4
    cmp     eax, 33             ; 1 cmdId + 32 payload
    jne     .t1_fail
    ;; Verify cmdId
    cmp     byte [_proto_buf], 0x10
    jne     .t1_fail
    ;; Verify first byte of payload
    cmp     byte [_proto_buf+1], 'A'
    jne     .t1_fail
    ;; Verify last byte
    cmp     byte [_proto_buf+32], '5'
    jne     .t1_fail
    xor     eax, eax
    call    print_result
    jmp     .t2

.t1_fail:
    mov     eax, 1
    call    print_result

.t2:
    ;; T2: send 1-byte message (just cmdId, no payload)
    mov     esi, t2_name
    call    print

    push    0                   ; payload len = 0
    push    0                   ; payload ptr = NULL
    push    byte 0x50           ; CMD_PING
    push    dword [sock_pair]
    call    proto_send_msg
    add     esp, 16

    push    dword [sock_pair+4]
    call    proto_recv_msg
    add     esp, 4
    cmp     eax, 1              ; just cmdId
    jne     .t2_fail
    cmp     byte [_proto_buf], 0x50
    jne     .t2_fail
    xor     eax, eax
    call    print_result
    jmp     .done

.t2_fail:
    mov     eax, 1
    call    print_result

.done:
.bail:
    push    0
    call    [os_vtable.exit]
