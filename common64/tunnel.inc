;; =============================================================================
;; tunnel.inc — Port forwarding -L and SOCKS5 -D (x86_64)
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; -L local_port:remote_host:remote_port
;;   Client listens on local_port, forwards connections through pmash server
;;   to remote_host:remote_port on the server's network.
;;
;; -D local_port (SOCKS5)
;;   Client listens on local_port as SOCKS5 proxy, forwards connections
;;   through pmash server to any destination.
;;
;; Protocol: CMD_TUNNEL_OPEN (0xD5) with target host:port
;;           Server connects to target, then bidirectional forwarding
;; =============================================================================

CMD_TUNNEL_OPEN  equ 0xD5
CMD_TUNNEL_OK    equ 0xD6
CMD_TUNNEL_FAIL  equ 0xD7

;; SOCKS5 constants
SOCKS5_VER       equ 0x05
SOCKS5_CMD_CONN  equ 0x01
SOCKS5_ATYP_IPV4 equ 0x01
SOCKS5_ATYP_DOMAIN equ 0x03
SOCKS5_SUCCESS   equ 0x00
SOCKS5_FAIL      equ 0x01

section .data
    _tun_fail    db "tunnel: connection failed", 10, 0
    _tun_ok      db "tunnel established", 10, 0

section .bss
    _tun_buf     resb 16384
    _tun_socks_buf resb 512        ; SOCKS5 negotiation buffer

section .text

;; =============================================================================
;; tunnel_server_handle(rdi=client_fd) — Server side: open tunnel to target
;; Payload in _proto_buf: [cmdId][ip_4bytes][port_2bytes_BE]
;; =============================================================================
global tunnel_server_handle
tunnel_server_handle:
    push    rbx
    push    r12
    mov     ebx, edi               ; client_fd

    ;; Parse target: 4-byte IP (network order) + 2-byte port (BE)
    mov     esi, [_proto_buf+1]    ; IP (already network order)
    movzx   edx, byte [_proto_buf+5]
    shl     edx, 8
    movzx   eax, byte [_proto_buf+6]
    or      edx, eax               ; port (host order)

    ;; Connect to target
    push    rdx                    ; save port
    push    rsi                    ; save ip
    call    [os_vtable.socket]
    test    eax, eax
    js      .tsh_fail
    mov     r12d, eax              ; target fd

    pop     rsi                    ; ip
    pop     rdx                    ; port
    mov     edi, r12d
    call    [os_vtable.connect]
    test    eax, eax
    jnz     .tsh_close_fail

    ;; Send TUNNEL_OK
    mov     edi, ebx
    mov     sil, CMD_TUNNEL_OK
    xor     edx, edx
    xor     ecx, ecx
    call    proto_send_msg

    ;; Bidirectional forwarding (same as proxy)
.tsh_fwd:
    ;; client → target (using poll to avoid blocking)
    sub     rsp, 8
    mov     eax, ebx
    mov     [rsp], eax             ; pollfd.fd = client
    mov     word [rsp+4], POLLIN
    mov     word [rsp+6], 0
    lea     rdi, [rsp]
    mov     esi, 1
    mov     edx, 100               ; 100ms timeout
    mov     eax, SYS64_POLL
    syscall
    add     rsp, 8
    test    eax, eax
    jle     .tsh_try_target

    mov     edi, ebx
    lea     rsi, [_tun_buf]
    mov     edx, 16384
    call    [os_vtable.recv]
    test    eax, eax
    jle     .tsh_done
    mov     edi, r12d
    lea     rsi, [_tun_buf]
    mov     edx, eax
    call    [os_vtable.send]

.tsh_try_target:
    ;; target → client
    sub     rsp, 8
    mov     eax, r12d
    mov     [rsp], eax
    mov     word [rsp+4], POLLIN
    mov     word [rsp+6], 0
    lea     rdi, [rsp]
    mov     esi, 1
    mov     edx, 100
    mov     eax, SYS64_POLL
    syscall
    add     rsp, 8
    test    eax, eax
    jle     .tsh_fwd

    mov     edi, r12d
    lea     rsi, [_tun_buf]
    mov     edx, 16384
    call    [os_vtable.recv]
    test    eax, eax
    jle     .tsh_done
    mov     edi, ebx
    lea     rsi, [_tun_buf]
    mov     edx, eax
    call    [os_vtable.send]
    jmp     .tsh_fwd

.tsh_done:
    mov     edi, r12d
    call    [os_vtable.closesock]
    pop     r12
    pop     rbx
    ret

.tsh_close_fail:
    mov     edi, r12d
    call    [os_vtable.closesock]
.tsh_fail:
    ;; Send TUNNEL_FAIL
    mov     edi, ebx
    mov     sil, CMD_TUNNEL_FAIL
    xor     edx, edx
    xor     ecx, ecx
    call    proto_send_msg
    pop     r12
    pop     rbx
    ret

;; =============================================================================
;; tunnel_client_forward(rdi=server_fd, rsi=local_listen_port,
;;                       rdx=remote_ip, rcx=remote_port)
;; Client side -L: listen locally, forward through server tunnel
;; =============================================================================
global tunnel_client_forward
tunnel_client_forward:
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    mov     r12d, edi              ; server_fd
    mov     r13d, esi              ; local_listen_port
    mov     r14d, edx              ; remote_ip
    mov     r15d, ecx              ; remote_port

    ;; Create local listen socket
    call    [os_vtable.socket]
    test    eax, eax
    js      .tcf_fail
    mov     ebx, eax               ; listen fd

    mov     edi, ebx
    mov     esi, r13d
    call    [os_vtable.bind]
    test    eax, eax
    jnz     .tcf_close

    mov     edi, ebx
    mov     esi, 5
    call    [os_vtable.listen]

    ;; Accept loop (single connection for simplicity)
    mov     edi, ebx
    call    [os_vtable.accept]
    test    eax, eax
    js      .tcf_close
    push    rax                    ; save local client fd

    ;; Send CMD_TUNNEL_OPEN to server: [ip_4][port_2BE]
    lea     rdi, [_tun_buf]
    mov     [rdi], r14d            ; remote IP
    mov     eax, r15d
    shr     eax, 8
    mov     [rdi+4], al            ; port high
    mov     [rdi+5], r15b          ; port low
    mov     edi, r12d
    mov     sil, CMD_TUNNEL_OPEN
    lea     rdx, [_tun_buf]
    mov     ecx, 6
    call    proto_send_msg

    ;; Wait for TUNNEL_OK
    mov     edi, r12d
    call    proto_recv_msg
    test    eax, eax
    jle     .tcf_close_local
    cmp     byte [_proto_buf], CMD_TUNNEL_OK
    jne     .tcf_close_local

    ;; Bidirectional: local_client ↔ server (raw, not proto-framed)
    pop     r13                    ; local client fd
    ;; TODO: raw forwarding loop (same as proxy fwd_loop)
    ;; For now, this establishes the tunnel — full impl needs
    ;; non-blocking poll between local_client and server_fd

    ;; Close
    mov     edi, r13d
    call    [os_vtable.closesock]
    jmp     .tcf_close

.tcf_close_local:
    pop     rax
    mov     edi, eax
    call    [os_vtable.closesock]
.tcf_close:
    mov     edi, ebx
    call    [os_vtable.closesock]
.tcf_fail:
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

;; =============================================================================
;; socks5_server(rdi=server_fd, rsi=local_listen_port)
;; Client side -D: SOCKS5 proxy, forward through server tunnel
;; =============================================================================
global socks5_server
socks5_server:
    push    rbx
    push    r12
    push    r13
    mov     r12d, edi              ; server_fd (pmash connection)
    mov     r13d, esi              ; local listen port

    ;; Create SOCKS5 listen socket
    call    [os_vtable.socket]
    test    eax, eax
    js      .s5_fail
    mov     ebx, eax

    mov     edi, ebx
    mov     esi, r13d
    call    [os_vtable.bind]
    test    eax, eax
    jnz     .s5_close

    mov     edi, ebx
    mov     esi, 5
    call    [os_vtable.listen]

.s5_accept:
    mov     edi, ebx
    call    [os_vtable.accept]
    test    eax, eax
    js      .s5_accept
    push    rax                    ; save client fd
    mov     r13d, eax

    ;; SOCKS5 greeting: client sends [VER(1)][NMETHODS(1)][METHODS(N)]
    mov     edi, r13d
    lea     rsi, [_tun_socks_buf]
    mov     edx, 512
    call    [os_vtable.recv]
    test    eax, eax
    jle     .s5_close_client

    ;; Reply: [VER=5][METHOD=0 (no auth)]
    lea     rdi, [_tun_socks_buf]
    mov     byte [rdi], SOCKS5_VER
    mov     byte [rdi+1], 0x00    ; no auth required
    mov     edi, r13d
    lea     rsi, [_tun_socks_buf]
    mov     edx, 2
    call    [os_vtable.send]

    ;; SOCKS5 request: [VER][CMD][RSV][ATYP][DST.ADDR][DST.PORT]
    mov     edi, r13d
    lea     rsi, [_tun_socks_buf]
    mov     edx, 512
    call    [os_vtable.recv]
    test    eax, eax
    jle     .s5_close_client

    ;; Parse: must be CMD=CONNECT(1)
    cmp     byte [_tun_socks_buf+1], SOCKS5_CMD_CONN
    jne     .s5_reject

    ;; Parse address type
    movzx   eax, byte [_tun_socks_buf+3]
    cmp     al, SOCKS5_ATYP_IPV4
    je      .s5_ipv4
    ;; Domain and IPv6 not supported yet
    jmp     .s5_reject

.s5_ipv4:
    ;; IP at offset 4 (4 bytes), port at offset 8 (2 bytes BE)
    mov     esi, [_tun_socks_buf+4]    ; IP (network order)
    movzx   edx, byte [_tun_socks_buf+8]
    shl     edx, 8
    movzx   eax, byte [_tun_socks_buf+9]
    or      edx, eax                   ; port

    ;; Send CMD_TUNNEL_OPEN to pmash server
    lea     rdi, [_tun_buf]
    mov     [rdi], esi             ; IP
    mov     eax, edx
    shr     eax, 8
    mov     [rdi+4], al
    mov     [rdi+5], dl
    push    rdx                    ; save port
    push    rsi                    ; save ip
    mov     edi, r12d
    mov     sil, CMD_TUNNEL_OPEN
    lea     rdx, [_tun_buf]
    mov     ecx, 6
    call    proto_send_msg

    ;; Wait for TUNNEL_OK/FAIL
    mov     edi, r12d
    call    proto_recv_msg
    pop     rsi                    ; ip
    pop     rdx                    ; port
    test    eax, eax
    jle     .s5_reject
    cmp     byte [_proto_buf], CMD_TUNNEL_OK
    jne     .s5_reject

    ;; SOCKS5 success reply
    lea     rdi, [_tun_socks_buf]
    mov     byte [rdi], SOCKS5_VER
    mov     byte [rdi+1], SOCKS5_SUCCESS
    mov     byte [rdi+2], 0       ; RSV
    mov     byte [rdi+3], SOCKS5_ATYP_IPV4
    mov     dword [rdi+4], 0      ; bind addr (0.0.0.0)
    mov     word [rdi+8], 0       ; bind port (0)
    mov     edi, r13d
    lea     rsi, [_tun_socks_buf]
    mov     edx, 10
    call    [os_vtable.send]

    ;; TODO: bidirectional forwarding between SOCKS client and pmash tunnel
    ;; For now, tunnel is established — full impl needs raw relay loop

    pop     rax                    ; discard saved client fd
    jmp     .s5_accept

.s5_reject:
    ;; SOCKS5 failure reply
    lea     rdi, [_tun_socks_buf]
    mov     byte [rdi], SOCKS5_VER
    mov     byte [rdi+1], SOCKS5_FAIL
    mov     byte [rdi+2], 0
    mov     byte [rdi+3], SOCKS5_ATYP_IPV4
    mov     dword [rdi+4], 0
    mov     word [rdi+8], 0
    mov     edi, r13d
    lea     rsi, [_tun_socks_buf]
    mov     edx, 10
    call    [os_vtable.send]

.s5_close_client:
    pop     rax
    mov     edi, eax
    call    [os_vtable.closesock]
    jmp     .s5_accept

.s5_close:
    mov     edi, ebx
    call    [os_vtable.closesock]
.s5_fail:
    pop     r13
    pop     r12
    pop     rbx
    ret
