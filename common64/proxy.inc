;; =============================================================================
;; proxy.inc — ProxyJump tunnel (OS-agnostic via vtable, x86_64)
;; Part of pmash — lightweight remote agent
;; =============================================================================

CMD_PROXY_CONNECT equ 0xD0
CMD_PROXY_OK      equ 0xD1

DEFAULT_PROXY_PORT equ 8822

section .data
    _proxy_fail db "proxy: connection to target failed", 0

section .bss
    _proxy_buf resb 16384

section .text

;; proxy_handle(rdi=client_fd)
global proxy_handle
proxy_handle:
    push    rbx
    push    r12
    mov     ebx, edi               ; client_fd

    ;; Parse target host from _proto_buf
    lea     rsi, [_proto_buf+1]    ; skip cmdId
    movzx   eax, byte [rsi]
    shl     eax, 8
    movzx   ecx, byte [rsi+1]
    or      eax, ecx
    add     rsi, 2
    mov     byte [rsi+rax], 0      ; null-terminate

    ;; Connect to target
    call    [os_vtable.socket]
    test    eax, eax
    js      .proxy_fail
    mov     r12d, eax              ; target fd

    ;; Connect (placeholder: 127.0.0.1)
    mov     edi, r12d
    mov     esi, 0x0100007F        ; 127.0.0.1 network order
    mov     edx, DEFAULT_PROXY_PORT
    call    [os_vtable.connect]
    test    eax, eax
    jnz     .proxy_close

    ;; Send PROXY_OK
    mov     edi, ebx
    mov     sil, CMD_PROXY_OK
    xor     edx, edx
    xor     ecx, ecx
    call    proto_send_msg

    ;; Bidirectional forwarding loop
.fwd_loop:
    ;; client → target
    mov     edi, ebx
    lea     rsi, [_proxy_buf]
    mov     edx, 16384
    call    [os_vtable.recv]
    test    eax, eax
    jle     .fwd_done
    mov     edi, r12d
    lea     rsi, [_proxy_buf]
    mov     edx, eax
    call    [os_vtable.send]

    ;; target → client
    mov     edi, r12d
    lea     rsi, [_proxy_buf]
    mov     edx, 16384
    call    [os_vtable.recv]
    test    eax, eax
    jle     .fwd_done
    mov     edi, ebx
    lea     rsi, [_proxy_buf]
    mov     edx, eax
    call    [os_vtable.send]
    jmp     .fwd_loop

.fwd_done:
.proxy_close:
    mov     edi, r12d
    call    [os_vtable.closesock]
    pop     r12
    pop     rbx
    ret

.proxy_fail:
    lea     rdi, [_proxy_fail]
    call    pm_strlen
    mov     edi, ebx
    mov     sil, CMD_ERROR
    lea     rdx, [_proxy_fail]
    mov     ecx, eax
    call    proto_send_msg
    pop     r12
    pop     rbx
    ret
