;; =============================================================================
;; proto.inc — Binary wire protocol for pmash Linux
;; Part of pmash — lightweight remote agent (Linux port)
;; =============================================================================
;; Wire format: 4-byte BE length + payload
;; Payload: 1-byte command ID + variable data
;; Same protocol as Windows pmash — full interop
;; =============================================================================

;; Command IDs (must match Windows version)
CMD_AUTH_REQUEST    equ 0x01
CMD_AUTH_CHALLENGE  equ 0x02
CMD_AUTH_RESPONSE   equ 0x03
CMD_AUTH_OK         equ 0x04
CMD_AUTH_FAIL       equ 0x05
CMD_EXEC            equ 0x10
CMD_EXEC_RESULT     equ 0x11
CMD_EXEC_EXIT       equ 0x12
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
CMD_SCREENSHOT_REQ  equ 0x60
CMD_SCREENSHOT_DATA equ 0x61
CMD_SELF_UPDATE     equ 0x70
CMD_WRITE           equ 0xA0
CMD_WRITE_OK        equ 0xA1
CMD_NATIVE          equ 0xB0
CMD_NATIVE_RESP     equ 0xB1
CMD_ERROR           equ 0xFF

section .bss
    _proto_hdr  resb 4          ; 4-byte length header
    _proto_buf  resb 65536      ; message buffer

section .text

;; =============================================================================
;; proto_send — Send length-prefixed message over socket
;; Args: rdi = fd, rsi = buf (cmdId + payload), rdx = len
;; Returns: 0 on success, -1 on error
;; =============================================================================
proto_send:
    push    rbx
    push    r12
    push    r13
    mov     r12, rdi            ; fd
    mov     r13, rsi            ; buf
    mov     rbx, rdx            ; len

    ;; Write 4-byte BE length header
    mov     eax, ebx
    bswap   eax
    mov     [_proto_hdr], eax
    mov     rdi, r12
    lea     rsi, [_proto_hdr]
    mov     rdx, 4
    call    send_all
    test    rax, rax
    js      .fail

    ;; Write payload
    mov     rdi, r12
    mov     rsi, r13
    mov     rdx, rbx
    call    send_all
    test    rax, rax
    js      .fail

    xor     rax, rax
    pop     r13
    pop     r12
    pop     rbx
    ret
.fail:
    mov     rax, -1
    pop     r13
    pop     r12
    pop     rbx
    ret

;; =============================================================================
;; proto_recv — Receive length-prefixed message from socket
;; Args: rdi = fd
;; Returns: rax = message length (including cmdId), data in _proto_buf
;;          rax = -1 on error, 0 on connection closed
;; =============================================================================
proto_recv:
    push    rbx
    push    r12
    mov     r12, rdi            ; fd

    ;; Read 4-byte length header
    lea     rsi, [_proto_hdr]
    mov     rdx, 4
    call    recv_all
    cmp     rax, 4
    jne     .fail

    ;; Decode length (BE)
    mov     eax, [_proto_hdr]
    bswap   eax
    mov     ebx, eax            ; message length

    ;; Sanity check
    cmp     ebx, 65536
    ja      .fail
    test    ebx, ebx
    jz      .fail

    ;; Read payload
    mov     rdi, r12
    lea     rsi, [_proto_buf]
    mov     edx, ebx
    call    recv_all
    cmp     rax, rbx
    jne     .fail

    mov     rax, rbx            ; return message length
    pop     r12
    pop     rbx
    ret
.fail:
    mov     rax, -1
    pop     r12
    pop     rbx
    ret

;; =============================================================================
;; proto_send_msg — Send cmdId + payload as a protocol message
;; Args: rdi = fd, sil = cmdId, rdx = payload ptr, rcx = payload len
;; =============================================================================
proto_send_msg:
    push    rbx
    push    r12
    push    r13
    push    r14
    mov     r12, rdi            ; fd
    mov     r13b, sil           ; cmdId
    mov     r14, rdx            ; payload
    mov     rbx, rcx            ; payload len

    ;; Build message: [cmdId][payload]
    lea     rdi, [_proto_buf]
    mov     byte [rdi], r13b    ; cmdId
    ;; Copy payload if any
    test    rbx, rbx
    jz      .send
    lea     rdi, [_proto_buf + 1]
    mov     rsi, r14
    mov     rdx, rbx
    call    memcpy
.send:
    mov     rdi, r12
    lea     rsi, [_proto_buf]
    lea     rdx, [rbx + 1]     ; total = 1 + payload_len
    call    proto_send

    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

;; =============================================================================
;; send_all — Write all bytes to fd (handles partial writes)
;; Args: rdi = fd, rsi = buf, rdx = len
;; Returns: rax = total bytes sent, -1 on error
;; =============================================================================
send_all:
    push    rbx
    push    r12
    push    r13
    mov     r12, rdi            ; fd
    mov     r13, rsi            ; buf
    mov     rbx, rdx            ; remaining
    xor     r14, r14            ; total sent (not used as return but for tracking)
.loop:
    test    rbx, rbx
    jle     .done
    mov     rdi, r12
    mov     rsi, r13
    mov     rdx, rbx
    mov     rax, SYS_WRITE
    syscall
    test    rax, rax
    jle     .err
    add     r13, rax
    sub     rbx, rax
    jmp     .loop
.done:
    mov     rax, r13
    sub     rax, rsi            ; doesn't work after push... just return 0 for success
    xor     rax, rax
    pop     r13
    pop     r12
    pop     rbx
    ret
.err:
    mov     rax, -1
    pop     r13
    pop     r12
    pop     rbx
    ret

;; =============================================================================
;; recv_all — Read exactly N bytes from fd
;; Args: rdi = fd, rsi = buf, rdx = len
;; Returns: rax = total bytes read
;; =============================================================================
recv_all:
    push    rbx
    push    r12
    push    r13
    push    r14
    mov     r12, rdi            ; fd
    mov     r13, rsi            ; buf
    mov     rbx, rdx            ; remaining
    xor     r14, r14            ; total read
.loop:
    test    rbx, rbx
    jle     .done
    mov     rdi, r12
    mov     rsi, r13
    mov     rdx, rbx
    mov     rax, SYS_READ
    syscall
    test    rax, rax
    jle     .done               ; EOF or error
    add     r13, rax
    add     r14, rax
    sub     rbx, rax
    jmp     .loop
.done:
    mov     rax, r14
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret
