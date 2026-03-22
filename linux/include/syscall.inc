;; =============================================================================
;; syscall.inc — Linux x86_64 system call numbers + helpers
;; Part of pmash — lightweight remote agent (Linux port)
;; =============================================================================

;; System call numbers (x86_64)
SYS_READ        equ 0
SYS_WRITE       equ 1
SYS_OPEN        equ 2
SYS_CLOSE       equ 3
SYS_STAT        equ 4
SYS_FSTAT       equ 5
SYS_LSEEK       equ 8
SYS_MMAP        equ 9
SYS_MUNMAP      equ 11
SYS_SOCKET      equ 41
SYS_CONNECT     equ 42
SYS_ACCEPT      equ 43
SYS_SENDTO      equ 44
SYS_RECVFROM    equ 45
SYS_BIND        equ 49
SYS_LISTEN      equ 50
SYS_SETSOCKOPT  equ 54
SYS_CLONE       equ 56
SYS_FORK        equ 57
SYS_EXECVE      equ 59
SYS_EXIT        equ 60
SYS_WAIT4       equ 61
SYS_KILL        equ 62
SYS_GETPID      equ 39
SYS_PIPE        equ 22
SYS_DUP2        equ 33
SYS_NANOSLEEP   equ 35
SYS_RENAME      equ 82
SYS_UNLINK      equ 87
SYS_MKDIR       equ 83
SYS_GETDENTS64  equ 217

;; Socket constants
AF_INET         equ 2
SOCK_STREAM     equ 1
SOCK_DGRAM      equ 2
IPPROTO_TCP     equ 6
IPPROTO_UDP     equ 17
SOL_SOCKET      equ 1
SO_REUSEADDR    equ 2
SO_RCVTIMEO     equ 20

;; Open flags
O_RDONLY        equ 0
O_WRONLY        equ 1
O_RDWR          equ 2
O_CREAT         equ 64
O_TRUNC         equ 512

;; File permissions
S_IRWXU         equ 448     ; 0700

;; sockaddr_in structure (16 bytes)
struc sockaddr_in
    .sin_family resw 1
    .sin_port   resw 1
    .sin_addr   resd 1
    .sin_zero   resb 8
endstruc

;; =============================================================================
;; Macros for syscalls (x86_64: rax=nr, rdi/rsi/rdx/r10/r8/r9 = args)
;; =============================================================================

%macro sys_exit 1
    mov     rdi, %1
    mov     rax, SYS_EXIT
    syscall
%endmacro

%macro sys_write 3          ; fd, buf, len
    mov     rdi, %1
    mov     rsi, %2
    mov     rdx, %3
    mov     rax, SYS_WRITE
    syscall
%endmacro

%macro sys_read 3           ; fd, buf, len
    mov     rdi, %1
    mov     rsi, %2
    mov     rdx, %3
    mov     rax, SYS_READ
    syscall
%endmacro
