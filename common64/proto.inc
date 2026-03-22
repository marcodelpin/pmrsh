;; =============================================================================
;; proto.inc — Binary wire protocol (OS-agnostic via vtable, x86_64)
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; Wire format: [4-byte BE length][1-byte cmdId][payload]
;; =============================================================================

;; Command IDs (must match all pmash implementations)
CMD_AUTH_REQUEST    equ 0x01
CMD_AUTH_CHALLENGE  equ 0x02
CMD_AUTH_RESPONSE   equ 0x03
CMD_AUTH_OK         equ 0x04
CMD_AUTH_FAIL       equ 0x05
CMD_EXEC            equ 0x10
CMD_EXEC_RESULT     equ 0x11
CMD_PUSH_START      equ 0x20
CMD_PUSH_DATA       equ 0x21
CMD_PUSH_END        equ 0x22
CMD_PUSH_OK         equ 0x23
CMD_PULL_REQ        equ 0x30
CMD_PULL_DATA       equ 0x31
CMD_PULL_END        equ 0x32
CMD_INFO_REQ        equ 0x40
CMD_INFO_RESP       equ 0x41
CMD_PING            equ 0x50
CMD_PONG            equ 0x51
CMD_WRITE           equ 0xA0
CMD_WRITE_OK        equ 0xA1
CMD_NATIVE          equ 0xB0
CMD_NATIVE_RESP     equ 0xB1
CMD_INPUT           equ 0xC0
CMD_INPUT_RESP      equ 0xC1
CMD_ERROR           equ 0xFF

section .bss
    _proto_hdr  resb 4           ; 4-byte length header
    _proto_buf  resb 65536       ; message buffer

section .text

;; =============================================================================
;; proto_send_all(rdi=fd, rsi=buf, rdx=len) → rax=0/-1
;; =============================================================================
global proto_send_all
proto_send_all:
    push    rbx
    push    r12
    push    r13
    mov     r12d, edi              ; fd
    mov     r13, rsi               ; buf
    mov     ebx, edx               ; remaining len
.loop:
    test    ebx, ebx
    jle     .done
    mov     edi, r12d
    mov     rsi, r13
    mov     edx, ebx
    call    [os_vtable.send]
    test    eax, eax
    jle     .err
    add     r13, rax
    sub     ebx, eax
    jmp     .loop
.done:
    xor     eax, eax
    pop     r13
    pop     r12
    pop     rbx
    ret
.err:
    mov     eax, -1
    pop     r13
    pop     r12
    pop     rbx
    ret

;; =============================================================================
;; proto_recv_all(rdi=fd, rsi=buf, rdx=len) → rax = bytes read
;; =============================================================================
global proto_recv_all
proto_recv_all:
    push    rbx
    push    r12
    push    r13
    push    r14
    mov     r12d, edi              ; fd
    mov     r13, rsi               ; buf
    mov     r14d, edx              ; remaining
    xor     ebx, ebx              ; total read
.loop:
    test    r14d, r14d
    jle     .done
    mov     edi, r12d
    mov     rsi, r13
    mov     edx, r14d
    call    [os_vtable.recv]
    test    eax, eax
    jle     .done
    add     r13, rax
    add     ebx, eax
    sub     r14d, eax
    jmp     .loop
.done:
    mov     eax, ebx
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

;; =============================================================================
;; proto_send_msg(rdi=fd, rsi=cmdId, rdx=payload_ptr, rcx=payload_len)
;; =============================================================================
global proto_send_msg
proto_send_msg:
    push    rbx
    push    r12
    push    r13
    push    r14
    mov     r12d, edi              ; fd
    mov     r13b, sil              ; cmdId
    mov     r14, rdx               ; payload ptr
    mov     ebx, ecx               ; payload len

    ;; Build message: [cmdId][payload] in _proto_buf
    mov     [_proto_buf], r13b
    test    ebx, ebx
    jz      .send
    lea     rdi, [_proto_buf+1]
    mov     rsi, r14
    mov     ecx, ebx
    rep movsb
.send:
    ;; Total message size = 1 + payload_len
    lea     eax, [ebx+1]
    mov     r14d, eax              ; save total msg size

    ;; Write 4-byte BE length header
    bswap   eax
    mov     [_proto_hdr], eax
    mov     edi, r12d
    lea     rsi, [_proto_hdr]
    mov     edx, 4
    call    proto_send_all
    test    eax, eax
    jnz     .fail

    ;; Write message body
    mov     edi, r12d
    lea     rsi, [_proto_buf]
    mov     edx, r14d
    call    proto_send_all

    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret
.fail:
    mov     eax, -1
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

;; =============================================================================
;; proto_recv_msg(rdi=fd) → rax = message length (data in _proto_buf)
;; =============================================================================
global proto_recv_msg
proto_recv_msg:
    push    rbx
    mov     ebx, edi               ; fd

    ;; Read 4-byte header
    mov     edi, ebx
    lea     rsi, [_proto_hdr]
    mov     edx, 4
    call    proto_recv_all
    cmp     eax, 4
    jne     .fail

    ;; Decode BE length
    mov     eax, [_proto_hdr]
    bswap   eax
    cmp     eax, 65536
    ja      .fail
    test    eax, eax
    jz      .fail

    ;; Read payload
    mov     edx, eax               ; len
    mov     edi, ebx
    lea     rsi, [_proto_buf]
    call    proto_recv_all
    ;; eax = bytes read
    pop     rbx
    ret

.fail:
    mov     eax, -1
    pop     rbx
    ret
