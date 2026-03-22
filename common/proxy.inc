;; =============================================================================
;; proxy.inc — ProxyJump: tunnel through intermediate host (OS-agnostic)
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; Server receives CMD_PROXY_CONNECT, connects to target, forwards bidirectionally.
;; Uses vtable for socket ops. No threading — uses blocking I/O with select-like poll.
;; =============================================================================

CMD_PROXY_CONNECT equ 0xD0
CMD_PROXY_OK      equ 0xD1

DEFAULT_PROXY_PORT equ 8822

section .data
    _proxy_fail db "proxy: connection to target failed", 0

section .bss
    _proxy_buf resb 16384           ; forwarding buffer

section .text

;; =============================================================================
;; proxy_handle — Server-side: receive PROXY_CONNECT, tunnel to target
;; Args on stack: (client_fd)
;; Payload of CMD_PROXY_CONNECT: encode_str(target_host)
;; Does NOT return until tunnel closes.
;; =============================================================================
global proxy_handle
proxy_handle:
    push    ebx
    push    esi
    push    edi
    push    ebp
    mov     ebp, [esp+20]       ; client_fd

    ;; Parse target host from _proto_buf
    lea     esi, [_proto_buf+1]  ; skip cmdId
    movzx   eax, byte [esi]
    shl     eax, 8
    movzx   ecx, byte [esi+1]
    or      eax, ecx            ; host string length
    add     esi, 2
    mov     byte [esi+eax], 0   ; null-terminate

    ;; TODO: resolve hostname to IP (would need DNS via vtable)
    ;; For now, assume target is reachable via direct connect
    ;; Connect to target on default port
    call    [os_vtable.socket]
    test    eax, eax
    js      .proxy_fail
    mov     edi, eax            ; target fd

    ;; Connect (using IP 127.0.0.1 as placeholder — real impl needs DNS)
    push    DEFAULT_PROXY_PORT
    push    0x0100007F          ; 127.0.0.1 in network byte order
    push    edi
    call    [os_vtable.connect]
    add     esp, 12
    test    eax, eax
    jnz     .proxy_close

    ;; Auth with target (simplified: just forward raw bytes)
    ;; Send PROXY_OK to client
    push    0
    push    0
    push    byte CMD_PROXY_OK
    push    ebp                 ; client_fd
    call    proto_send_msg
    add     esp, 16

    ;; Bidirectional forwarding loop
    ;; Simple approach: alternate read from client and target
    ;; (real impl would use select/poll/epoll)
.fwd_loop:
    ;; Try read from client → write to target
    push    16384
    push    _proxy_buf
    push    ebp                 ; client_fd
    call    [os_vtable.recv]
    add     esp, 12
    test    eax, eax
    jle     .fwd_done
    push    eax
    push    _proxy_buf
    push    edi                 ; target_fd
    call    [os_vtable.send]
    add     esp, 12

    ;; Try read from target → write to client
    push    16384
    push    _proxy_buf
    push    edi                 ; target_fd
    call    [os_vtable.recv]
    add     esp, 12
    test    eax, eax
    jle     .fwd_done
    push    eax
    push    _proxy_buf
    push    ebp                 ; client_fd
    call    [os_vtable.send]
    add     esp, 12
    jmp     .fwd_loop

.fwd_done:
.proxy_close:
    push    edi
    call    [os_vtable.closesock]
    add     esp, 4
    pop     ebp
    pop     edi
    pop     esi
    pop     ebx
    ret

.proxy_fail:
    ;; Send error to client
    mov     esi, _proxy_fail
    call    pm_strlen
    push    eax
    push    _proxy_fail
    push    byte CMD_ERROR
    push    ebp
    call    proto_send_msg
    add     esp, 16
    pop     ebp
    pop     edi
    pop     esi
    pop     ebx
    ret
