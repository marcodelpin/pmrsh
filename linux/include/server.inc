;; =============================================================================
;; server.inc — Server loop: accept, dispatch commands (plaintext)
;; Part of pmash — lightweight remote agent (Linux port)
;; =============================================================================
;; No TLS for Linux MVP — plaintext binary protocol over TCP.
;; TLS can be added later via BearSSL static lib.
;; =============================================================================

section .data
    _info_fmt   db '{"hostname":"'
    _info_mid   db '","version":"pmash 0.1.0","os":"Linux"}', 0
    _pong_str   db "pong", 0
    _err_str    db "unknown command", 0

section .bss
    _srv_hostname resb 256
    _srv_info_buf resb 512
    _srv_msg_buf  resb 65536    ; working buffer for responses

section .text

;; =============================================================================
;; server_loop — Listen, accept, dispatch commands
;; Args: rdi = port (16-bit)
;; =============================================================================
server_loop:
    push    rbx
    push    r12
    push    r13
    push    r14
    mov     r14w, di            ; port

    ;; Create listen socket
    call    net_socket
    test    rax, rax
    js      .fail
    mov     r12, rax            ; listen fd

    ;; Set SO_REUSEADDR
    sub     rsp, 8
    mov     dword [rsp], 1
    mov     rdi, r12
    mov     rsi, SOL_SOCKET
    mov     rdx, SO_REUSEADDR
    lea     r10, [rsp]
    mov     r8, 4
    mov     rax, SYS_SETSOCKOPT
    syscall
    add     rsp, 8

    ;; Bind to 0.0.0.0:port
    sub     rsp, 16             ; sockaddr_in on stack
    mov     word [rsp], AF_INET
    movzx   edi, r14w
    call    htons
    mov     [rsp + 2], ax
    mov     dword [rsp + 4], 0  ; INADDR_ANY
    mov     qword [rsp + 8], 0  ; sin_zero

    mov     rdi, r12
    mov     rsi, rsp
    mov     rdx, 16
    call    net_bind
    test    rax, rax
    js      .close_listen

    ;; Listen
    mov     rdi, r12
    mov     rsi, 5              ; backlog
    call    net_listen
    test    rax, rax
    js      .close_listen

    add     rsp, 16             ; free sockaddr

.accept_loop:
    ;; Accept connection
    mov     rdi, r12
    xor     rsi, rsi
    xor     rdx, rdx
    call    net_accept
    test    rax, rax
    js      .accept_loop
    mov     r13, rax            ; client fd

    ;; Command dispatch loop
.cmd_loop:
    mov     rdi, r13
    call    proto_recv
    test    rax, rax
    jle     .disconnect

    ;; Parse cmdId (first byte of _proto_buf)
    movzx   eax, byte [_proto_buf]

    cmp     al, CMD_AUTH_REQUEST
    je      .handle_auth
    cmp     al, CMD_PING
    je      .handle_ping
    cmp     al, CMD_EXEC
    je      .handle_exec
    cmp     al, CMD_INFO_REQ
    je      .handle_info
    ;; Unknown command → error
    jmp     .handle_unknown

.handle_auth:
    ;; MVP: accept all auth requests (no verification)
    ;; Send AUTH_CHALLENGE (32 zero bytes)
    lea     rdi, [_srv_msg_buf]
    xor     rsi, rsi
    mov     rdx, 32
    call    memset
    mov     rdi, r13
    mov     sil, CMD_AUTH_CHALLENGE
    lea     rdx, [_srv_msg_buf]
    mov     rcx, 32
    call    proto_send_msg

    ;; Receive AUTH_RESPONSE (ignore signature)
    mov     rdi, r13
    call    proto_recv
    test    rax, rax
    jle     .disconnect

    ;; Send AUTH_OK: encode_str("pmash 0.1.0") + caps(0) + no_banner(0)
    lea     rdi, [_srv_msg_buf]
    mov     byte [rdi], 0       ; str len high
    mov     byte [rdi + 1], 11  ; str len low = 11
    lea     rsi, [.auth_ver]
    lea     rdi, [_srv_msg_buf + 2]
    mov     rdx, 11
    call    memcpy
    lea     rdi, [_srv_msg_buf]
    mov     byte [rdi + 13], 0  ; caps_count = 0
    mov     byte [rdi + 14], 0  ; no_banner = 0
    mov     rdi, r13
    mov     sil, CMD_AUTH_OK
    lea     rdx, [_srv_msg_buf]
    mov     rcx, 15
    call    proto_send_msg
    jmp     .cmd_loop

.handle_ping:
    mov     rdi, r13
    mov     sil, CMD_PONG
    xor     rdx, rdx
    xor     rcx, rcx
    call    proto_send_msg
    jmp     .cmd_loop

.handle_exec:
    ;; Parse exec payload: 2-byte BE string len + command string
    movzx   eax, byte [_proto_buf + 1]
    shl     eax, 8
    movzx   ecx, byte [_proto_buf + 2]
    or      eax, ecx            ; command length
    lea     rdi, [_proto_buf + 3]
    mov     byte [rdi + rax], 0 ; null-terminate

    ;; Execute command
    call    exec_command
    test    rax, rax
    js      .exec_fail

    ;; Build EXEC_RESULT: exit_code(4 LE) + blob(4 BE + data)
    mov     rbx, rax            ; output length
    lea     rdi, [_srv_msg_buf]
    mov     dword [rdi], 0      ; exit_code = 0 (LE)
    mov     eax, ebx
    bswap   eax
    mov     [rdi + 4], eax      ; blob length (BE)
    ;; Copy output
    lea     rdi, [_srv_msg_buf + 8]
    lea     rsi, [_exec_buf]
    mov     rdx, rbx
    call    memcpy

    ;; Send response
    mov     rdi, r13
    mov     sil, CMD_EXEC_RESULT
    lea     rdx, [_srv_msg_buf]
    lea     rcx, [rbx + 8]     ; payload = 4 + 4 + output_len
    call    proto_send_msg
    jmp     .cmd_loop

.exec_fail:
    ;; Send error
    lea     rdi, [_err_str]
    call    strlen
    mov     rbx, rax
    ;; encode_str(error)
    lea     rdi, [_srv_msg_buf]
    mov     byte [rdi], 0
    mov     [rdi + 1], bl       ; 2-byte BE len (< 256)
    lea     rsi, [_err_str]
    lea     rdi, [_srv_msg_buf + 2]
    mov     rdx, rbx
    call    memcpy

    mov     rdi, r13
    mov     sil, CMD_ERROR
    lea     rdx, [_srv_msg_buf]
    lea     rcx, [rbx + 2]
    call    proto_send_msg
    jmp     .cmd_loop

.handle_info:
    ;; Get hostname
    lea     rdi, [_srv_hostname]
    mov     rsi, 255
    ;; Use uname syscall would be complex — just read /etc/hostname
    push    r13
    mov     rdi, 0              ; AT_FDCWD not needed, use open
    lea     rdi, [.hostname_path]
    mov     rsi, O_RDONLY
    xor     rdx, rdx
    mov     rax, SYS_OPEN
    syscall
    test    rax, rax
    js      .info_fallback
    mov     r13, rax            ; fd
    mov     rdi, rax
    lea     rsi, [_srv_hostname]
    mov     rdx, 255
    mov     rax, SYS_READ
    syscall
    ;; Strip newline
    test    rax, rax
    jle     .info_close
    dec     rax
    mov     byte [_srv_hostname + rax], 0
.info_close:
    mov     rdi, r13
    mov     rax, SYS_CLOSE
    syscall
    pop     r13
    jmp     .info_build

.info_fallback:
    pop     r13
    mov     byte [_srv_hostname], '?'
    mov     byte [_srv_hostname + 1], 0

.info_build:
    ;; Build JSON: {"hostname":"<name>","version":"pmash 0.1.0","os":"Linux"}
    lea     rdi, [_srv_info_buf]
    lea     rsi, [_info_fmt]
    mov     rcx, 14             ; length of '{"hostname":"'
    call    memcpy
    add     rdi, 14
    ;; Copy hostname
    push    rdi
    lea     rdi, [_srv_hostname]
    call    strlen
    mov     rbx, rax
    pop     rdi
    lea     rsi, [_srv_hostname]
    mov     rdx, rbx
    call    memcpy
    add     rdi, rbx
    ;; Copy suffix
    lea     rsi, [_info_mid]
    push    rdi
    lea     rdi, [_info_mid]
    call    strlen
    mov     rcx, rax
    pop     rdi
    mov     rdx, rcx
    lea     rsi, [_info_mid]
    call    memcpy
    add     rdi, rdx

    ;; Total length
    lea     rax, [_srv_info_buf]
    sub     rdi, rax
    mov     rbx, rdi

    ;; Send as INFO_RESP
    mov     rdi, r13
    mov     sil, CMD_INFO_RESP
    lea     rdx, [_srv_info_buf]
    mov     rcx, rbx
    call    proto_send_msg
    jmp     .cmd_loop

.handle_unknown:
    lea     rdi, [_err_str]
    call    strlen
    mov     rbx, rax
    lea     rdi, [_srv_msg_buf]
    mov     byte [rdi], 0
    mov     [rdi + 1], bl
    lea     rdi, [_srv_msg_buf + 2]
    lea     rsi, [_err_str]
    mov     rdx, rbx
    call    memcpy
    mov     rdi, r13
    mov     sil, CMD_ERROR
    lea     rdx, [_srv_msg_buf]
    lea     rcx, [rbx + 2]
    call    proto_send_msg
    jmp     .cmd_loop

.disconnect:
    mov     rdi, r13
    call    net_close
    jmp     .accept_loop

.close_listen:
    mov     rdi, r12
    call    net_close
.fail:
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

section .data
.hostname_path db "/etc/hostname", 0
.auth_ver      db "pmash 0.1.0", 0
