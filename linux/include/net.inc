;; =============================================================================
;; net.inc — TCP networking via Linux syscalls
;; Part of pmash — lightweight remote agent (Linux port)
;; =============================================================================
;; Direct syscalls, no libc. All network I/O is blocking.
;; =============================================================================

section .text

;; =============================================================================
;; net_socket — Create TCP socket
;; Returns: fd in rax, -1 on error
;; =============================================================================
net_socket:
    mov     rdi, AF_INET
    mov     rsi, SOCK_STREAM
    mov     rdx, IPPROTO_TCP
    mov     rax, SYS_SOCKET
    syscall
    ret

;; =============================================================================
;; net_connect — Connect to host:port
;; Args: rdi = socket fd, rsi = ptr to sockaddr_in, rdx = sizeof sockaddr_in
;; Returns: 0 on success, -1 on error
;; =============================================================================
net_connect:
    mov     rax, SYS_CONNECT
    syscall
    ret

;; =============================================================================
;; net_bind — Bind socket to address
;; Args: rdi = socket fd, rsi = ptr to sockaddr_in, rdx = sizeof sockaddr_in
;; =============================================================================
net_bind:
    mov     rax, SYS_BIND
    syscall
    ret

;; =============================================================================
;; net_listen — Listen on socket
;; Args: rdi = socket fd, rsi = backlog
;; =============================================================================
net_listen:
    mov     rax, SYS_LISTEN
    syscall
    ret

;; =============================================================================
;; net_accept — Accept connection
;; Args: rdi = listen fd, rsi = ptr to sockaddr_in (or 0), rdx = ptr to addrlen (or 0)
;; Returns: new fd in rax
;; =============================================================================
net_accept:
    mov     rax, SYS_ACCEPT
    syscall
    ret

;; =============================================================================
;; net_send — Send data
;; Args: rdi = fd, rsi = buf, rdx = len
;; Returns: bytes sent in rax
;; =============================================================================
net_send:
    mov     rax, SYS_WRITE      ; write() works for connected sockets
    syscall
    ret

;; =============================================================================
;; net_recv — Receive data
;; Args: rdi = fd, rsi = buf, rdx = len
;; Returns: bytes received in rax (0 = closed)
;; =============================================================================
net_recv:
    mov     rax, SYS_READ       ; read() works for connected sockets
    syscall
    ret

;; =============================================================================
;; net_close — Close socket
;; Args: rdi = fd
;; =============================================================================
net_close:
    mov     rax, SYS_CLOSE
    syscall
    ret
