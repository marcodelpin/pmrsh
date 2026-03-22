;; =============================================================================
;; main-unified.asm — pmash unified binary (vtable-based)
;; Single source → builds for Linux (and eventually Windows via APE)
;; =============================================================================

bits 32

;; OS layer
%include "vtable.inc"
%include "linux.inc"

;; Common modules (OS-agnostic)
%include "../common/util.inc"
%include "../common/hash.inc"
%include "../common/base64.inc"
%include "../common/protobuf.inc"
%include "../common/proto.inc"
%include "../common/sync.inc"
%include "../common/shell.inc"
%include "../common/proxy.inc"
%include "../common/relay.inc"
%include "../common/daemon.inc"
%include "../common/client.inc"
%include "../common/server.inc"

section .data
    ver_str     db "pmash 0.1.0 (unified)", 10, 0
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
    cli_cmd     resd 1          ; command name ptr
    cli_arg     resd 1          ; command arg ptr
    cli_argc    resd 1          ; saved argc
    cli_argv    resd 1          ; saved argv base

DEFAULT_PORT equ 8822

section .text
    global _start

_start:
    call    detect_os
    call    patch_vtable

    pop     ecx                 ; argc
    mov     [cli_argc], ecx
    mov     [cli_argv], esp     ; argv base

    ;; Defaults
    mov     word [cli_port], DEFAULT_PORT
    mov     dword [cli_host], 0
    mov     dword [cli_cmd], 0
    mov     dword [cli_arg], 0

    cmp     ecx, 2
    jl      .show_usage

    ;; Parse all args
    mov     ebx, 1              ; start at argv[1]
.parse_loop:
    cmp     ebx, ecx
    jge     .parse_done
    mov     edi, [esp + ebx*4]  ; argv[n]

    ;; --version
    push    ecx
    push    ebx
    mov     esi, flag_ver
    call    .strcmp
    pop     ebx
    pop     ecx
    test    eax, eax
    jz      .print_version

    ;; --listen
    push    ecx
    push    ebx
    mov     esi, flag_listen
    call    .strcmp
    pop     ebx
    pop     ecx
    test    eax, eax
    jz      .parse_listen

    ;; --daemon
    push    ecx
    push    ebx
    mov     esi, flag_daemon
    call    .strcmp
    pop     ebx
    pop     ecx
    test    eax, eax
    jz      .parse_daemon

    ;; -h
    push    ecx
    push    ebx
    mov     esi, flag_h
    call    .strcmp
    pop     ebx
    pop     ecx
    test    eax, eax
    jz      .parse_host

    ;; -p
    push    ecx
    push    ebx
    mov     esi, flag_p
    call    .strcmp
    pop     ebx
    pop     ecx
    test    eax, eax
    jz      .parse_port

    ;; Positional: command or arg
    cmp     dword [cli_cmd], 0
    jne     .set_arg
    mov     [cli_cmd], edi
    jmp     .next_arg
.set_arg:
    mov     [cli_arg], edi
.next_arg:
    inc     ebx
    jmp     .parse_loop

.parse_host:
    inc     ebx
    cmp     ebx, ecx
    jge     .err_nohost
    mov     edi, [esp + ebx*4]
    ;; Convert dotted IP string to network order
    ;; Simple: parse "A.B.C.D" → 4 bytes
    push    ecx
    push    ebx
    mov     esi, edi
    call    .parse_ip
    mov     [cli_host], eax
    pop     ebx
    pop     ecx
    jmp     .next_arg

.parse_port:
    inc     ebx
    cmp     ebx, ecx
    jge     .err_port
    mov     esi, [esp + ebx*4]
    push    ecx
    push    ebx
    call    pm_atoi
    mov     [cli_port], ax
    pop     ebx
    pop     ecx
    jmp     .next_arg

.parse_listen:
    inc     ebx
    cmp     ebx, ecx
    jge     .err_port
    mov     esi, [esp + ebx*4]
    call    pm_atoi
    push    eax
    call    server_run

.parse_daemon:
    inc     ebx
    cmp     ebx, ecx
    jge     .err_port
    push    ecx
    push    ebx
    mov     esi, [esp + ebx*4 + 8]  ; adjust for 2 pushes
    call    pm_atoi
    push    eax                 ; save port
    call    daemonize
    pop     eax                 ; restore port
    pop     ebx
    pop     ecx
    push    eax
    call    server_run

.parse_done:
    ;; Client mode — need host + command
    cmp     dword [cli_host], 0
    je      .show_usage
    cmp     dword [cli_cmd], 0
    je      .show_usage

    ;; Connect + run command
    push    dword [cli_arg]
    push    dword [cli_cmd]
    movzx   eax, word [cli_port]
    push    eax
    push    dword [cli_host]
    call    client_run
    ;; noreturn

.print_version:
    mov     esi, ver_str
    call    pm_stdout
    push    0
    call    [os_vtable.exit]

.show_usage:
    mov     esi, usage_str
    call    pm_stderr
    push    1
    call    [os_vtable.exit]

.err_port:
    mov     esi, err_noport
    call    pm_stderr
    push    1
    call    [os_vtable.exit]

.err_nohost:
    mov     esi, err_nohost
    call    pm_stderr
    push    1
    call    [os_vtable.exit]

;; strcmp(edi, esi) → eax (0=match)
.strcmp:
    xor     ecx, ecx
.cmp_loop:
    mov     al, [edi+ecx]
    cmp     al, [esi+ecx]
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

;; parse_ip(esi = "A.B.C.D") → eax = network order IP
.parse_ip:
    push    ebx
    xor     eax, eax
    xor     ebx, ebx            ; current octet
    xor     ecx, ecx            ; byte position (0-3)
.ip_loop:
    movzx   edx, byte [esi]
    inc     esi
    cmp     dl, '.'
    je      .ip_dot
    cmp     dl, 0
    je      .ip_end
    ;; Accumulate digit
    imul    ebx, 10
    sub     dl, '0'
    add     ebx, edx
    jmp     .ip_loop
.ip_dot:
    ;; Store octet (network order = first byte at lowest address)
    shl     eax, 8
    or      eax, ebx
    xor     ebx, ebx
    inc     ecx
    jmp     .ip_loop
.ip_end:
    shl     eax, 8
    or      eax, ebx
    ;; Shift produced big-endian (network order): "192.168.71.127" → 0xC0A84F7F
    ;; sockaddr_in.sin_addr expects network order — no bswap needed
    pop     ebx
    ret
