;; =============================================================================
;; daemon.inc — Daemonize process (x86_64)
;; Part of pmash — lightweight remote agent
;; =============================================================================

section .data
    _daemon_devnull db "/dev/null", 0
    _daemon_pidfile db "/var/run/pmash.pid", 0

section .text

;; daemonize() → rax=0 in child, parent exits
global daemonize
daemonize:
    cmp     dword [_os_type], OS_LINUX
    jne     .noop

    ;; Fork
    mov     eax, SYS64_FORK
    syscall
    test    eax, eax
    js      .fail
    jnz     .parent

    ;; Child: create new session
    mov     eax, SYS64_SETSID
    syscall

    xor     eax, eax
    ret

.parent:
    xor     edi, edi
    mov     eax, SYS64_EXIT
    syscall

.fail:
    mov     eax, -1
    ret

.noop:
    xor     eax, eax
    ret
