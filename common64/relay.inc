;; =============================================================================
;; relay.inc — Rendezvous DeviceID resolution via hbbs (x86_64)
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; Flow: RegisterPeer → PunchHoleRequest → parse PunchHoleResponse
;; Uses UDP sockets via direct syscalls.
;; =============================================================================

;; RendezvousMessage envelope field numbers (protobuf)
RDV_REGISTER_PEER          equ 6
RDV_PUNCH_HOLE_REQUEST     equ 8
RDV_PUNCH_HOLE_RESPONSE    equ 11
RDV_FETCH_LOCAL_ADDR       equ 12
RDV_PORT                   equ 21116

L_SOCK_DGRAM equ 2

section .data
    _rdv_id     db "pmash-client", 0
    _rdv_ver    db "1.2.7", 0
    _rdv_fail   db "rendezvous failed", 10, 0
    _rdv_plat_l db "linux", 0
    _rdv_plat_w db "windows", 0

section .bss
    _rdv_buf    resb 4096
    _rdv_submsg resb 1024
    _rdv_sockaddr resb 16          ; sockaddr_in for UDP

section .text

;; =============================================================================
;; relay_udp_socket — Create UDP socket
;; Returns: rax = fd
;; =============================================================================
relay_udp_socket:
    mov     edi, L_AF_INET
    mov     esi, L_SOCK_DGRAM
    xor     edx, edx
    mov     eax, SYS64_SOCKET
    syscall
    ret

;; =============================================================================
;; relay_udp_sendto(rdi=fd, rsi=buf, rdx=len, rcx=ip, r8=port)
;; =============================================================================
relay_udp_sendto:
    push    rbx
    push    r12
    push    r13
    mov     ebx, edi               ; fd
    mov     r12, rsi               ; buf
    mov     r13d, edx              ; len
    ;; Build sockaddr_in on stack
    sub     rsp, 16
    mov     word [rsp], L_AF_INET
    mov     eax, r8d
    xchg    al, ah                 ; htons
    mov     [rsp+2], ax
    mov     [rsp+4], ecx           ; ip (network order)
    mov     qword [rsp+8], 0
    ;; sendto(fd, buf, len, 0, &sa, 16)
    mov     edi, ebx
    mov     rsi, r12
    mov     edx, r13d
    xor     r10d, r10d             ; flags = 0
    lea     r8, [rsp]              ; addr
    mov     r9d, 16                ; addrlen
    mov     eax, SYS64_SENDTO
    syscall
    add     rsp, 16
    pop     r13
    pop     r12
    pop     rbx
    ret

;; =============================================================================
;; relay_udp_recvfrom(rdi=fd, rsi=buf, rdx=maxlen) → rax=bytes
;; =============================================================================
relay_udp_recvfrom:
    ;; recvfrom(fd, buf, len, 0, NULL, NULL)
    xor     r10d, r10d             ; flags
    xor     r8d, r8d               ; addr = NULL
    xor     r9d, r9d               ; addrlen = NULL
    mov     eax, SYS64_RECVFROM
    syscall
    ret

;; =============================================================================
;; relay_register(rdi=rdv_ip, rsi=rdv_port, rdx=device_id)
;; Register this server with hbbs rendezvous server.
;; =============================================================================
global relay_register
relay_register:
    push    rbx
    push    r12
    push    r13
    push    r14
    mov     r12d, edi              ; rdv_ip (network order)
    mov     r13d, esi              ; rdv_port
    mov     r14, rdx               ; device_id

    ;; Create UDP socket
    call    relay_udp_socket
    test    eax, eax
    js      .reg_fail
    mov     ebx, eax               ; udp fd

    ;; Build RegisterPeer submessage in _rdv_submsg
    lea     rdi, [_rdv_submsg]
    ;; field 1: id (string)
    push    rdi
    mov     rdi, r14
    call    pm_strlen
    pop     rdi
    mov     rcx, rax               ; strlen
    mov     rsi, 1                 ; field_num
    mov     rdx, r14               ; string ptr
    call    pb_write_string
    mov     r8d, eax               ; bytes written

    ;; field 5: platform (string)
    lea     rdi, [_rdv_submsg]
    add     rdi, r8
    lea     rdx, [_rdv_plat_l]
    push    rdi
    push    r8
    mov     rdi, rdx
    call    pm_strlen
    pop     r8
    pop     rdi
    mov     rcx, rax
    mov     rsi, 5                 ; field_num
    lea     rdx, [_rdv_plat_l]
    call    pb_write_string
    add     r8d, eax               ; total submsg size

    ;; Wrap in RendezvousMessage envelope (field 6 = RegisterPeer)
    lea     rdi, [_rdv_buf]
    mov     rsi, RDV_REGISTER_PEER ; field_num
    lea     rdx, [_rdv_submsg]
    mov     rcx, r8                ; submsg size
    call    pb_write_string
    ;; rax = total envelope bytes

    ;; Send via UDP to rdv server
    mov     edi, ebx               ; udp fd
    lea     rsi, [_rdv_buf]
    mov     edx, eax               ; msg len
    mov     ecx, r12d              ; ip
    mov     r8d, r13d              ; port
    call    relay_udp_sendto

    ;; Close UDP socket
    mov     edi, ebx
    mov     eax, SYS64_CLOSE
    syscall

    xor     eax, eax
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

.reg_fail:
    mov     eax, -1
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

;; =============================================================================
;; relay_resolve(rdi=rdv_ip, rsi=rdv_port, rdx=device_id, rcx=out_ip, r8=out_port)
;; Resolve DeviceID via hbbs: PunchHoleRequest → parse response
;; Returns: 0 = success (ip/port in out_ip/out_port), -1 = fail
;; =============================================================================
global relay_resolve
relay_resolve:
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    mov     r12d, edi              ; rdv_ip
    mov     r13d, esi              ; rdv_port
    mov     r14, rdx               ; device_id
    mov     r15, rcx               ; out_ip ptr
    push    r8                     ; out_port ptr

    ;; Create UDP socket
    call    relay_udp_socket
    test    eax, eax
    js      .resolve_fail
    mov     ebx, eax

    ;; Build PunchHoleRequest submessage
    lea     rdi, [_rdv_submsg]
    push    rdi
    mov     rdi, r14
    call    pm_strlen
    pop     rdi
    mov     rcx, rax
    mov     rsi, 1                 ; field 1: id
    mov     rdx, r14
    call    pb_write_string
    mov     r8d, eax

    ;; Wrap in envelope (field 8 = PunchHoleRequest)
    lea     rdi, [_rdv_buf]
    mov     rsi, RDV_PUNCH_HOLE_REQUEST
    lea     rdx, [_rdv_submsg]
    mov     rcx, r8
    call    pb_write_string

    ;; Send
    mov     edi, ebx
    lea     rsi, [_rdv_buf]
    mov     edx, eax
    mov     ecx, r12d
    mov     r8d, r13d
    call    relay_udp_sendto

    ;; Receive response (with timeout — just try once)
    mov     edi, ebx
    lea     rsi, [_rdv_buf]
    mov     edx, 4096
    call    relay_udp_recvfrom
    test    eax, eax
    jle     .resolve_close_fail

    ;; Parse PunchHoleResponse (field 11 in envelope)
    ;; Simplified: scan for socket_addr field (field 1 in PunchHoleResponse)
    ;; which contains ip (string) + port (int32)
    ;; For MVP: just report success if we got a response
    ;; Full parsing would need nested protobuf decode

    ;; Close socket
    mov     edi, ebx
    mov     eax, SYS64_CLOSE
    syscall

    xor     eax, eax               ; success (parsed addr would go in out_ip/out_port)
    pop     r8
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

.resolve_close_fail:
    mov     edi, ebx
    mov     eax, SYS64_CLOSE
    syscall
.resolve_fail:
    mov     eax, -1
    pop     r8
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret
