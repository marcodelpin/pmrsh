;; =============================================================================
;; tls.inc — TLS integration via BearSSL wrapper (x86_64)
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; After TLS handshake, replaces vtable.send/recv with tls_send/tls_recv
;; so all protocol code transparently uses encrypted I/O.
;; =============================================================================

;; External C functions (from tls_wrapper.c)
extern tls_client_connect
extern tls_server_accept
extern tls_read
extern tls_write
extern tls_close

section .data
    _tls_enabled dd 0              ; 1 after successful handshake
    _tls_is_server dd 0            ; 0 = client, 1 = server

section .text

;; =============================================================================
;; tls_wrap_client(rdi=fd) → rax = 0 success, -1 fail
;; Performs TLS handshake as client, then patches vtable
;; =============================================================================
global tls_wrap_client
tls_wrap_client:
    push    rbx
    mov     ebx, edi               ; save fd
    call    tls_client_connect     ; rdi already = fd
    test    eax, eax
    jnz     .wrap_fail

    mov     dword [_tls_is_server], 0
    mov     dword [_tls_enabled], 1

    ;; Patch vtable: send → tls_send_wrapper, recv → tls_recv_wrapper
    lea     rax, [_tls_send_wrapper]
    mov     [os_vtable.send], rax
    lea     rax, [_tls_recv_wrapper]
    mov     [os_vtable.recv], rax

    xor     eax, eax
    pop     rbx
    ret
.wrap_fail:
    mov     eax, -1
    pop     rbx
    ret

;; =============================================================================
;; tls_wrap_server(rdi=fd) → rax = 0 success, -1 fail
;; Performs TLS handshake as server, then patches vtable
;; =============================================================================
global tls_wrap_server
tls_wrap_server:
    push    rbx
    mov     ebx, edi
    call    tls_server_accept
    test    eax, eax
    jnz     .swrap_fail

    mov     dword [_tls_is_server], 1
    mov     dword [_tls_enabled], 1

    lea     rax, [_tls_send_wrapper]
    mov     [os_vtable.send], rax
    lea     rax, [_tls_recv_wrapper]
    mov     [os_vtable.recv], rax

    xor     eax, eax
    pop     rbx
    ret
.swrap_fail:
    mov     eax, -1
    pop     rbx
    ret

;; =============================================================================
;; tls_unwrap() — Restore plain vtable send/recv, close TLS session
;; =============================================================================
global tls_unwrap
tls_unwrap:
    cmp     dword [_tls_enabled], 0
    je      .uw_done
    mov     edi, [_tls_is_server]
    call    tls_close
    ;; Restore original send/recv
    lea     rax, [_linux_send]
    mov     [os_vtable.send], rax
    lea     rax, [_linux_recv]
    mov     [os_vtable.recv], rax
    mov     dword [_tls_enabled], 0
.uw_done:
    ret

;; =============================================================================
;; _tls_send_wrapper(rdi=fd, rsi=buf, rdx=len) → rax = bytes sent
;; Redirects to tls_write (ignores fd, uses TLS context)
;; =============================================================================
_tls_send_wrapper:
    ;; tls_write(is_server, buf, len)
    push    rdx                    ; save len
    push    rsi                    ; save buf
    mov     edi, [_tls_is_server]
    pop     rsi                    ; buf
    pop     rdx                    ; len
    call    tls_write
    ret

;; =============================================================================
;; _tls_recv_wrapper(rdi=fd, rsi=buf, rdx=len) → rax = bytes read
;; =============================================================================
_tls_recv_wrapper:
    push    rdx
    push    rsi
    mov     edi, [_tls_is_server]
    pop     rsi                    ; buf
    pop     rdx                    ; len
    call    tls_read
    ret
