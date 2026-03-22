;; =============================================================================
;; main64.asm — pmash unified binary (x86_64)
;; Single source → builds for Linux x86_64
;; =============================================================================

bits 64
default rel

;; OS layer
%include "vtable64.inc"
%include "linux64.inc"

;; Common modules (OS-agnostic, x86_64)
%include "../common64/util.inc"
%include "../common64/hash.inc"
%include "../common64/base64.inc"
%include "../common64/protobuf.inc"
%include "../common64/proto.inc"
%include "../common64/sync.inc"
%include "../common64/shell.inc"
%include "../common64/proxy.inc"
%include "../common64/relay.inc"
%include "../common64/compress.inc"
%include "../common64/blockcache.inc"
%include "../common64/daemon.inc"
%include "../common64/selfupdate.inc"
%include "../common64/auth.inc"
%include "../common64/client.inc"
%include "../common64/server.inc"

section .data
    ver_str     db "pmash 0.2.0 (x86_64)", 10, 0
    usage_str   db "Usage: pmash -h <host> [-p <port>] <command> [args]", 10
                db "       pmash --listen <port>", 10
                db "       pmash --daemon <port>", 10
                db "       pmash --version", 10
                db "Commands: exec, ping, info, ps, kill, push, pull, write, sync, shell", 10, 0
    flag_ver    db "--version", 0
    flag_listen db "--listen", 0
    flag_daemon db "--daemon", 0
    flag_h      db "-h", 0
    flag_p      db "-p", 0
    err_noport  db "Error: --listen/--daemon requires port", 10, 0
    err_nohost  db "Error: -h requires hostname/IP", 10, 0

section .bss
    cli_host    resd 1          ; host IP (network order)
    cli_port    resw 1          ; port (default 8822)
    cli_cmd     resq 1          ; command name ptr
    cli_arg     resq 1          ; command arg ptr
    cli_argc    resd 1          ; saved argc
    cli_argv    resq 1          ; saved argv base

DEFAULT_PORT equ 8822

section .text
    global _start

_start:
    call    detect_os
    call    patch_vtable

    ;; x86_64 Linux: argc at [rsp], argv at [rsp+8], [rsp+16], ...
    mov     ecx, [rsp]             ; argc
    mov     [cli_argc], ecx
    lea     rax, [rsp+8]           ; argv base
    mov     [cli_argv], rax

    ;; Resolve auth key paths from $HOME environment
    ;; envp = argv + (argc+1)*8
    mov     edi, ecx
    inc     edi                    ; argc+1 (skip NULL terminator)
    shl     rdi, 3                 ; * 8
    add     rdi, rax               ; envp = argv_base + (argc+1)*8
    call    auth_resolve_paths

    ;; Defaults
    mov     word [cli_port], DEFAULT_PORT
    mov     dword [cli_host], 0
    mov     qword [cli_cmd], 0
    mov     qword [cli_arg], 0

    cmp     ecx, 2
    jl      .show_usage

    ;; Parse args
    mov     r8, [cli_argv]         ; argv base
    mov     ebx, 1                 ; start at argv[1]
.parse_loop:
    cmp     ebx, ecx
    jge     .parse_done
    mov     rdi, [r8 + rbx*8]     ; argv[n]

    ;; --version
    push    rcx
    push    rbx
    push    r8
    lea     rsi, [flag_ver]
    call    .strcmp
    pop     r8
    pop     rbx
    pop     rcx
    test    eax, eax
    jz      .print_version

    ;; --listen
    mov     rdi, [r8 + rbx*8]
    push    rcx
    push    rbx
    push    r8
    lea     rsi, [flag_listen]
    call    .strcmp
    pop     r8
    pop     rbx
    pop     rcx
    test    eax, eax
    jz      .parse_listen

    ;; --daemon
    mov     rdi, [r8 + rbx*8]
    push    rcx
    push    rbx
    push    r8
    lea     rsi, [flag_daemon]
    call    .strcmp
    pop     r8
    pop     rbx
    pop     rcx
    test    eax, eax
    jz      .parse_daemon

    ;; -h
    mov     rdi, [r8 + rbx*8]
    push    rcx
    push    rbx
    push    r8
    lea     rsi, [flag_h]
    call    .strcmp
    pop     r8
    pop     rbx
    pop     rcx
    test    eax, eax
    jz      .parse_host

    ;; -p
    mov     rdi, [r8 + rbx*8]
    push    rcx
    push    rbx
    push    r8
    lea     rsi, [flag_p]
    call    .strcmp
    pop     r8
    pop     rbx
    pop     rcx
    test    eax, eax
    jz      .parse_port

    ;; Positional: command or arg
    mov     rdi, [r8 + rbx*8]
    cmp     qword [cli_cmd], 0
    jne     .set_arg
    mov     [cli_cmd], rdi
    jmp     .next_arg
.set_arg:
    mov     [cli_arg], rdi
.next_arg:
    inc     ebx
    jmp     .parse_loop

.parse_host:
    inc     ebx
    cmp     ebx, ecx
    jge     .err_nohost
    mov     rdi, [r8 + rbx*8]
    push    rcx
    push    rbx
    push    r8
    call    .parse_ip
    mov     [cli_host], eax
    pop     r8
    pop     rbx
    pop     rcx
    jmp     .next_arg

.parse_port:
    inc     ebx
    cmp     ebx, ecx
    jge     .err_port
    mov     rdi, [r8 + rbx*8]
    push    rcx
    push    rbx
    push    r8
    call    pm_atoi
    mov     [cli_port], ax
    pop     r8
    pop     rbx
    pop     rcx
    jmp     .next_arg

.parse_listen:
    inc     ebx
    cmp     ebx, ecx
    jge     .err_port
    mov     rdi, [r8 + rbx*8]
    call    pm_atoi
    mov     edi, eax
    call    server_run
    ;; noreturn

.parse_daemon:
    inc     ebx
    cmp     ebx, ecx
    jge     .err_port
    push    rcx
    push    rbx
    push    r8
    mov     rdi, [r8 + rbx*8]
    call    pm_atoi
    push    rax                    ; save port
    call    daemonize
    pop     rdi                    ; port
    pop     r8
    pop     rbx
    pop     rcx
    call    server_run
    ;; noreturn

.parse_done:
    cmp     dword [cli_host], 0
    je      .show_usage
    cmp     qword [cli_cmd], 0
    je      .show_usage

    ;; Client mode
    mov     edi, [cli_host]
    movzx   esi, word [cli_port]
    mov     rdx, [cli_cmd]
    mov     rcx, [cli_arg]
    call    client_run
    ;; noreturn

.print_version:
    lea     rdi, [ver_str]
    call    pm_stdout
    xor     edi, edi
    call    [os_vtable.exit]

.show_usage:
    lea     rdi, [usage_str]
    call    pm_stderr
    mov     edi, 1
    call    [os_vtable.exit]

.err_port:
    lea     rdi, [err_noport]
    call    pm_stderr
    mov     edi, 1
    call    [os_vtable.exit]

.err_nohost:
    lea     rdi, [err_nohost]
    call    pm_stderr
    mov     edi, 1
    call    [os_vtable.exit]

;; strcmp(rdi, rsi) → eax (0=match)
.strcmp:
    xor     ecx, ecx
.cmp_loop:
    mov     al, [rdi+rcx]
    cmp     al, [rsi+rcx]
    jne     .cmp_ne
    test    al, al
    jz      .cmp_eq
    inc     ecx
    jmp     .cmp_loop
.cmp_eq:
    xor     eax, eax
    ret
.cmp_ne:
    mov     eax, 1
    ret

;; parse_ip(rdi = "A.B.C.D") → eax = network order IP
.parse_ip:
    xor     eax, eax
    xor     ebx, ebx               ; current octet
    xor     ecx, ecx               ; byte position
    mov     rsi, rdi
.ip_loop:
    movzx   edx, byte [rsi]
    inc     rsi
    cmp     dl, '.'
    je      .ip_dot
    cmp     dl, 0
    je      .ip_end
    imul    ebx, 10
    sub     dl, '0'
    add     ebx, edx
    jmp     .ip_loop
.ip_dot:
    shl     eax, 8
    or      eax, ebx
    xor     ebx, ebx
    inc     ecx
    jmp     .ip_loop
.ip_end:
    shl     eax, 8
    or      eax, ebx
    bswap   eax                    ; host → network order
    ret
