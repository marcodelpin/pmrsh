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
%include "../common/server.inc"

section .data
    ver_str     db "pmash 0.1.0 (unified)", 10, 0
    usage_str   db "Usage: pmash --listen <port>", 10
                db "       pmash --version", 10, 0
    flag_ver    db "--version", 0
    flag_listen db "--listen", 0
    err_noport  db "Error: --listen requires port", 10, 0

section .text
    global _start

_start:
    ;; 1. Detect OS + patch vtable
    call    detect_os
    call    patch_vtable

    ;; 2. Parse args
    pop     ecx                 ; argc
    mov     esi, esp            ; argv[0..N]

    cmp     ecx, 2
    jl      .show_usage

    ;; argv[1]
    mov     edi, [esi+4]

    ;; Check --version
    push    edi
    mov     esi, flag_ver
    call    .strcmp
    pop     edi
    test    eax, eax
    jz      .print_version

    ;; Check --listen
    push    edi
    mov     esi, flag_listen
    call    .strcmp
    pop     edi
    test    eax, eax
    jz      .do_listen

    jmp     .show_usage

.do_listen:
    cmp     ecx, 3
    jl      .err_port
    ;; argv[2] = port
    mov     esi, [esp+8]        ; argv[2] — esp is argv base, +0=prog, +4=argv1, +8=argv2
    call    pm_atoi
    push    eax
    call    server_run
    ;; noreturn (server_run loops forever)

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
