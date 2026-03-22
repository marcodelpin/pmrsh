;; =============================================================================
;; linux64.inc — Linux x86_64 syscall implementations
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; System V AMD64 ABI: rdi, rsi, rdx, r10, r8, r9 for syscall args
;; syscall instruction (not int 0x80). Clobbers rcx and r11.
;; Direct socket syscalls (no socketcall multiplexer needed on x86_64).
;; =============================================================================

;; Linux x86_64 syscall numbers
SYS64_READ      equ 0
SYS64_WRITE     equ 1
SYS64_OPEN      equ 2
SYS64_CLOSE     equ 3
SYS64_LSEEK     equ 8
SYS64_MMAP      equ 9
SYS64_MUNMAP    equ 11
SYS64_BRK       equ 12
SYS64_PIPE      equ 22
SYS64_DUP2      equ 33
SYS64_NANOSLEEP equ 35
SYS64_FORK      equ 57
SYS64_EXECVE    equ 59
SYS64_EXIT      equ 60
SYS64_KILL      equ 62
SYS64_RENAME    equ 82
SYS64_MKDIR     equ 83
SYS64_UNLINK    equ 87
SYS64_READLINK  equ 89
SYS64_SETSID    equ 112
SYS64_GETPID    equ 39
SYS64_SOCKET    equ 41
SYS64_CONNECT   equ 42
SYS64_ACCEPT    equ 43
SYS64_SENDTO    equ 44
SYS64_RECVFROM  equ 45
SYS64_BIND      equ 49
SYS64_LISTEN    equ 50
SYS64_SETSOCKOPT equ 54
SYS64_WAIT4     equ 61
SYS64_FSTAT     equ 5
SYS64_GETHOSTNAME equ 170  ;; not a real syscall — use uname(63)
SYS64_UNAME     equ 63

;; Socket constants
L_AF_INET       equ 2
L_SOCK_STREAM   equ 1
L_SOL_SOCKET    equ 1
L_SO_REUSEADDR  equ 2

;; Open flags
L_O_RDONLY      equ 0
L_O_WRONLY      equ 1
L_O_RDWR        equ 2
L_O_CREAT       equ 64
L_O_TRUNC       equ 512

;; stat64 structure offset for st_size (struct stat on x86_64)
STAT64_SIZE_OFF equ 48
STAT64_STRUCT_SZ equ 144

section .bss
    _linux_stat_buf resb STAT64_STRUCT_SZ
    _linux_sa       resb 16         ; sockaddr_in
    _linux_ts       resb 16         ; timespec (64-bit: 2 x 8 bytes)
    _linux_hostbuf  resb 256
    _linux_brk_base resq 1          ; heap base
    _linux_brk_cur  resq 1          ; current brk
    _linux_uname    resb 390        ; struct utsname (65*6)

section .data
    _linux_sh_path  db "/bin/sh", 0
    _linux_sh_c     db "-c", 0
    _linux_etc_hostfile db "/etc/hostname", 0

section .text

;; =============================================================================
;; Vtable function calling convention for x86_64:
;; All vtable functions receive args via registers (System V ABI):
;;   arg1=rdi, arg2=rsi, arg3=rdx, arg4=rcx, arg5=r8, arg6=r9
;; Return value in rax.
;; =============================================================================

;; --- I/O ---

_linux_write:   ; (rdi=fd, rsi=buf, rdx=len) → rax=bytes written
    mov     eax, SYS64_WRITE
    syscall
    ret

_linux_read:    ; (rdi=fd, rsi=buf, rdx=len) → rax=bytes read
    mov     eax, SYS64_READ
    syscall
    ret

_linux_open:    ; (rdi=path, rsi=flags) → rax=fd
    ;; Map our flags: 0 → O_RDONLY, 1 → O_WRONLY|O_CREAT|O_TRUNC
    cmp     esi, 1
    jne     .open_do
    mov     esi, L_O_WRONLY | L_O_CREAT | L_O_TRUNC
.open_do:
    mov     edx, 0644o             ; mode (octal)
    mov     eax, SYS64_OPEN
    syscall
    ret

_linux_close:   ; (rdi=fd) → rax=0
    mov     eax, SYS64_CLOSE
    syscall
    ret

_linux_seek:    ; (rdi=fd, rsi=offset, rdx=whence) → rax=position
    mov     eax, SYS64_LSEEK
    syscall
    ret

_linux_filesize: ; (rdi=fd) → rax=size
    push    rbx
    mov     ebx, edi               ; save fd
    lea     rsi, [_linux_stat_buf]
    mov     eax, SYS64_FSTAT
    syscall
    test    eax, eax
    js      .fsize_fail
    mov     rax, [_linux_stat_buf + STAT64_SIZE_OFF]
    pop     rbx
    ret
.fsize_fail:
    mov     rax, -1
    pop     rbx
    ret

_linux_rename:  ; (rdi=old, rsi=new) → rax=0/err
    mov     eax, SYS64_RENAME
    syscall
    ret

_linux_unlink:  ; (rdi=path) → rax=0/err
    mov     eax, SYS64_UNLINK
    syscall
    ret

_linux_mkdir:   ; (rdi=path) → rax=0/err
    mov     esi, 0755o
    mov     eax, SYS64_MKDIR
    syscall
    ret

;; --- Network (direct syscalls, no socketcall multiplexer) ---

_linux_socket:  ; () → rax=fd
    mov     edi, L_AF_INET
    mov     esi, L_SOCK_STREAM
    xor     edx, edx               ; protocol = 0
    mov     eax, SYS64_SOCKET
    syscall
    ret

_linux_connect: ; (rdi=fd, rsi=ip, rdx=port) → rax=0/err
    push    rbx
    push    r12
    mov     ebx, edi               ; save fd
    mov     r12d, esi              ; save ip (network order)
    ;; Build sockaddr_in on stack (16 bytes)
    sub     rsp, 16
    mov     word [rsp], L_AF_INET  ; sin_family
    mov     eax, edx               ; port
    xchg    al, ah                 ; htons
    mov     [rsp+2], ax            ; sin_port
    mov     [rsp+4], r12d          ; sin_addr (network order)
    mov     qword [rsp+8], 0       ; padding
    ;; connect(fd, &sa, 16)
    mov     edi, ebx
    lea     rsi, [rsp]
    mov     edx, 16
    mov     eax, SYS64_CONNECT
    syscall
    add     rsp, 16
    pop     r12
    pop     rbx
    ret

_linux_bind:    ; (rdi=fd, rsi=port) → rax=0/err
    push    rbx
    push    r12
    mov     ebx, edi               ; save fd
    mov     r12d, esi              ; save port
    ;; setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &1, 4)
    sub     rsp, 16                ; space for optval + sockaddr
    mov     dword [rsp], 1         ; optval = 1
    mov     edi, ebx
    mov     esi, L_SOL_SOCKET
    mov     edx, L_SO_REUSEADDR
    lea     r10, [rsp]             ; optval ptr
    mov     r8d, 4                 ; optlen
    mov     eax, SYS64_SETSOCKOPT
    syscall
    ;; Build sockaddr_in
    mov     word [rsp], L_AF_INET
    mov     eax, r12d
    xchg    al, ah
    mov     [rsp+2], ax
    mov     dword [rsp+4], 0       ; INADDR_ANY
    mov     qword [rsp+8], 0
    ;; bind(fd, &sa, 16)
    mov     edi, ebx
    lea     rsi, [rsp]
    mov     edx, 16
    mov     eax, SYS64_BIND
    syscall
    add     rsp, 16
    pop     r12
    pop     rbx
    ret

_linux_listen:  ; (rdi=fd, rsi=backlog) → rax=0/err
    mov     eax, SYS64_LISTEN
    syscall
    ret

_linux_accept:  ; (rdi=fd) → rax=new_fd
    xor     esi, esi               ; addr = NULL
    xor     edx, edx               ; addrlen = NULL
    mov     eax, SYS64_ACCEPT
    syscall
    ret

_linux_send:    ; (rdi=fd, rsi=buf, rdx=len) → rax=bytes
    ;; For TCP, write() works fine
    mov     eax, SYS64_WRITE
    syscall
    ret

_linux_recv:    ; (rdi=fd, rsi=buf, rdx=len) → rax=bytes
    ;; For TCP, read() works fine
    mov     eax, SYS64_READ
    syscall
    ret

;; --- Process ---

_linux_exec:    ; (rdi=cmd, rsi=outbuf, rdx=outbufsize) → rax=output_len
    push    rbx
    push    r12
    push    r13
    push    r14
    mov     r12, rdi               ; cmd
    mov     r13, rsi               ; outbuf
    mov     r14d, edx              ; outbufsize

    ;; Create pipe: pipe(int pipefd[2])
    sub     rsp, 16                ; pipefd[0], pipefd[1] on stack
    lea     rdi, [rsp]
    mov     eax, SYS64_PIPE
    syscall
    test    eax, eax
    js      .exec_fail

    ;; Fork
    mov     eax, SYS64_FORK
    syscall
    test    eax, eax
    js      .exec_close_pipe
    jz      .exec_child

    ;; --- Parent ---
    ;; Close write end
    mov     edi, [rsp+4]
    mov     eax, SYS64_CLOSE
    syscall

    ;; Read output
    xor     ebx, ebx               ; total read
.exec_read:
    mov     edi, [rsp]             ; read fd
    lea     rsi, [r13+rbx]        ; outbuf + total
    mov     edx, 65536
    sub     edx, ebx
    jle     .exec_read_done
    mov     eax, SYS64_READ
    syscall
    test    eax, eax
    jle     .exec_read_done
    add     ebx, eax
    jmp     .exec_read

.exec_read_done:
    ;; Close read end
    mov     edi, [rsp]
    mov     eax, SYS64_CLOSE
    syscall
    ;; Wait for child
    mov     edi, -1                ; pid = -1 (any child)
    xor     esi, esi               ; status ptr
    xor     edx, edx               ; options
    xor     r10d, r10d             ; rusage
    mov     eax, SYS64_WAIT4
    syscall
    ;; Null-terminate
    mov     byte [r13+rbx], 0
    mov     eax, ebx
    add     rsp, 16
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

    ;; --- Child ---
.exec_child:
    ;; Close read end
    mov     edi, [rsp]
    mov     eax, SYS64_CLOSE
    syscall
    ;; dup2(write_fd, 1)
    mov     edi, [rsp+4]
    mov     esi, 1
    mov     eax, SYS64_DUP2
    syscall
    ;; dup2(write_fd, 2)
    mov     edi, [rsp+4]
    mov     esi, 2
    mov     eax, SYS64_DUP2
    syscall
    ;; Close original write fd
    mov     edi, [rsp+4]
    mov     eax, SYS64_CLOSE
    syscall
    ;; execve("/bin/sh", ["/bin/sh", "-c", cmd], NULL)
    sub     rsp, 32
    lea     rax, [_linux_sh_path]
    mov     [rsp], rax
    lea     rax, [_linux_sh_c]
    mov     [rsp+8], rax
    mov     [rsp+16], r12          ; cmd
    mov     qword [rsp+24], 0      ; NULL terminator
    lea     rdi, [_linux_sh_path]
    mov     rsi, rsp               ; argv
    xor     edx, edx               ; envp = NULL
    mov     eax, SYS64_EXECVE
    syscall
    ;; If execve fails, exit
    mov     edi, 127
    mov     eax, SYS64_EXIT
    syscall

.exec_close_pipe:
    mov     edi, [rsp]
    mov     eax, SYS64_CLOSE
    syscall
    mov     edi, [rsp+4]
    mov     eax, SYS64_CLOSE
    syscall
.exec_fail:
    mov     rax, -1
    add     rsp, 16
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

_linux_getpid:  ; () → rax=pid
    mov     eax, SYS64_GETPID
    syscall
    ret

_linux_exit:    ; (rdi=code) → noreturn
    mov     eax, SYS64_EXIT
    syscall

;; --- Memory (brk-based allocator) ---

_linux_alloc:   ; (rdi=size) → rax=ptr
    push    rbx
    push    r12
    mov     r12, rdi               ; save size
    ;; First call: get current brk
    cmp     qword [_linux_brk_base], 0
    jne     .alloc_have_base
    xor     edi, edi
    mov     eax, SYS64_BRK
    syscall
    mov     [_linux_brk_base], rax
    mov     [_linux_brk_cur], rax
.alloc_have_base:
    ;; Extend brk by size
    mov     rbx, [_linux_brk_cur]  ; save return ptr
    lea     rdi, [rbx + r12]       ; new brk
    mov     eax, SYS64_BRK
    syscall
    mov     [_linux_brk_cur], rax
    mov     rax, rbx               ; return old brk
    pop     r12
    pop     rbx
    ret

_linux_free:    ; (rdi=ptr) — no-op for brk allocator
    ret

_linux_sleep_ms: ; (rdi=ms)
    push    rbx
    mov     rax, rdi
    xor     edx, edx
    mov     ecx, 1000
    div     rcx                    ; rax = seconds, rdx = remainder ms
    lea     rbx, [_linux_ts]
    mov     [rbx], rax             ; tv_sec
    imul    rdx, 1000000           ; ms → ns
    mov     [rbx+8], rdx           ; tv_nsec
    mov     rdi, rbx               ; req
    xor     esi, esi               ; rem = NULL
    mov     eax, SYS64_NANOSLEEP
    syscall
    pop     rbx
    ret

_linux_hostname: ; (rdi=buf, rsi=len) → rax=actual_len
    push    rbx
    push    r12
    push    r13
    mov     r12, rdi               ; save buf
    mov     r13, rsi               ; save len
    ;; Read /etc/hostname
    lea     rdi, [_linux_etc_hostfile]
    xor     esi, esi               ; O_RDONLY
    mov     eax, SYS64_OPEN
    syscall
    test    eax, eax
    js      .host_fail
    mov     ebx, eax               ; save fd
    mov     edi, eax               ; fd
    mov     rsi, r12               ; buf
    mov     rdx, r13               ; len
    mov     eax, SYS64_READ
    syscall
    push    rax                    ; save bytes read
    mov     edi, ebx               ; fd
    mov     eax, SYS64_CLOSE
    syscall
    pop     rax
    ;; Strip trailing newline
    test    eax, eax
    jle     .host_fail
    dec     eax
    mov     byte [r12+rax], 0
    pop     r13
    pop     r12
    pop     rbx
    ret
.host_fail:
    xor     eax, eax
    pop     r13
    pop     r12
    pop     rbx
    ret
