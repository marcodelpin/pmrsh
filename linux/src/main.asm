;; =============================================================================
;; main.asm — pmash Linux entry point (x86_64 NASM)
;; Lightweight remote agent — Linux port
;; =============================================================================

bits 64
default rel

%include "syscall.inc"
%include "util.inc"
%include "net.inc"
%include "exec.inc"
%include "proto.inc"
%include "server.inc"

section .data
    version_str db "pmash 0.1.0 (linux)", 10, 0
    version_len equ 20

    usage_str   db "Usage: pmash -h <host> exec <cmd>", 10
                db "       pmash --listen <port>", 10
                db "       pmash --version", 10, 0
    usage_len   equ $ - usage_str

    err_nohost  db "Error: -h requires hostname", 10, 0
    err_noport  db "Error: --listen requires port", 10, 0

    flag_h      db "-h", 0
    flag_p      db "-p", 0
    flag_ver    db "--version", 0
    flag_listen db "--listen", 0

section .bss
    cli_host    resq 1          ; hostname ptr
    cli_port    resw 1          ; port (0 = default 8822)
    cli_command resq 1          ; command name ptr
    cli_arg1    resq 1          ; first arg ptr
    cli_mode    resb 1          ; 0=client, 1=server

DEFAULT_PORT equ 8822

section .text
    global _start

_start:
    ;; Get argc/argv from stack
    pop     rcx                 ; argc
    mov     r12, rcx            ; save argc
    mov     r13, rsp            ; argv starts here (argv[0] = program name)

    cmp     r12, 2
    jl      .show_usage

    ;; Parse arguments
    mov     rbx, 1              ; start at argv[1]
.parse_loop:
    cmp     rbx, r12
    jge     .parse_done
    mov     rdi, [r13 + rbx * 8]

    ;; --version
    lea     rsi, [flag_ver]
    call    strcmp
    test    rax, rax
    jz      .print_version

    ;; --listen
    lea     rsi, [flag_listen]
    call    strcmp
    test    rax, rax
    jz      .parse_listen

    ;; -h
    lea     rsi, [flag_h]
    call    strcmp
    test    rax, rax
    jz      .parse_host

    ;; -p
    lea     rsi, [flag_p]
    call    strcmp
    test    rax, rax
    jz      .parse_port

    ;; Positional arg: command or arg1
    cmp     qword [cli_command], 0
    jne     .set_arg1
    mov     [cli_command], rdi
    jmp     .next_arg
.set_arg1:
    mov     [cli_arg1], rdi
    jmp     .next_arg

.parse_host:
    inc     rbx
    cmp     rbx, r12
    jge     .err_nohost
    mov     rdi, [r13 + rbx * 8]
    mov     [cli_host], rdi
    jmp     .next_arg

.parse_port:
    inc     rbx
    cmp     rbx, r12
    jge     .show_usage
    mov     rdi, [r13 + rbx * 8]
    call    atoi
    mov     [cli_port], ax
    jmp     .next_arg

.parse_listen:
    mov     byte [cli_mode], 1
    inc     rbx
    cmp     rbx, r12
    jge     .err_noport
    mov     rdi, [r13 + rbx * 8]
    call    atoi
    mov     [cli_port], ax
    jmp     .next_arg

.next_arg:
    inc     rbx
    jmp     .parse_loop

.parse_done:
    ;; Dispatch based on mode
    cmp     byte [cli_mode], 1
    je      .start_server

    ;; Client mode — need host
    cmp     qword [cli_host], 0
    je      .show_usage
    ;; TODO: client connect + command dispatch
    ;; For now, show usage
    jmp     .show_usage

.start_server:
    movzx   edi, word [cli_port]
    test    edi, edi
    jz      .err_noport
    call    server_loop
    sys_exit 0

.print_version:
    lea     rdi, [version_str]
    call    stdout
    sys_exit 0

.show_usage:
    lea     rdi, [usage_str]
    call    stderr
    sys_exit 1

.err_nohost:
    lea     rdi, [err_nohost]
    call    stderr
    sys_exit 1

.err_noport:
    lea     rdi, [err_noport]
    call    stderr
    sys_exit 1

;; =============================================================================
;; strcmp — Compare two ASCIIZ strings
;; Args: rdi = str1, rsi = str2
;; Returns: rax = 0 if equal
;; =============================================================================
strcmp:
    xor     rcx, rcx
.loop:
    mov     al, [rdi + rcx]
    cmp     al, [rsi + rcx]
    jne     .ne
    test    al, al
    jz      .eq
    inc     rcx
    jmp     .loop
.eq:
    xor     rax, rax
    ret
.ne:
    mov     rax, 1
    ret
