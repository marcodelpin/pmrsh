;; =============================================================================
;; ratelimit.inc — Auth rate limiting (x86_64)
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; Tracks consecutive failed auth attempts. After MAX_FAIL_COUNT failures,
;; blocks further connections for BAN_DURATION_MS milliseconds.
;; Simple global counter (not per-IP — requires no IP parsing from accept).
;; =============================================================================

MAX_FAIL_COUNT   equ 5
BAN_DURATION_MS  equ 300000        ; 5 minutes

section .data
    _rl_fail_count dd 0
    _rl_banned     dd 0            ; 1 = currently banned
    _rl_ban_msg    db "rate limited: too many failed attempts", 10, 0

section .text

;; =============================================================================
;; rl_check_banned() → rax = 0 (ok) or 1 (banned)
;; If banned, sleeps BAN_DURATION_MS then resets.
;; =============================================================================
global rl_check_banned
rl_check_banned:
    cmp     dword [_rl_banned], 0
    je      .rl_ok

    ;; Banned — sleep then reset
    mov     edi, BAN_DURATION_MS
    call    [os_vtable.sleep_ms]
    mov     dword [_rl_banned], 0
    mov     dword [_rl_fail_count], 0

.rl_ok:
    xor     eax, eax
    ret

;; =============================================================================
;; rl_auth_failed() — Record a failed auth attempt
;; =============================================================================
global rl_auth_failed
rl_auth_failed:
    inc     dword [_rl_fail_count]
    mov     eax, [_rl_fail_count]
    cmp     eax, MAX_FAIL_COUNT
    jl      .rf_done
    ;; Threshold reached — ban
    mov     dword [_rl_banned], 1
.rf_done:
    ret

;; =============================================================================
;; rl_auth_succeeded() — Reset fail counter on successful auth
;; =============================================================================
global rl_auth_succeeded
rl_auth_succeeded:
    mov     dword [_rl_fail_count], 0
    mov     dword [_rl_banned], 0
    ret
