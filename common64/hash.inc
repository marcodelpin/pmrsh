;; =============================================================================
;; hash.inc — Adler32 checksum (OS-agnostic, pure math, x86_64)
;; Part of pmash — lightweight remote agent
;; =============================================================================

section .text

;; adler32(rdi=data, rsi=len) → eax = checksum
global adler32
adler32:
    push    rbx
    mov     eax, 1                 ; a = 1
    xor     ebx, ebx               ; b = 0
    mov     rcx, rsi               ; len
    mov     rsi, rdi               ; data ptr
    test    rcx, rcx
    jz      .done
.loop:
    movzx   edx, byte [rsi]
    add     eax, edx               ; a += byte
    add     ebx, eax               ; b += a
    ;; Modulo 65521 (Adler32 prime)
    push    rcx
    mov     ecx, 65521
    xor     edx, edx
    div     ecx                    ; eax = a / 65521
    mov     eax, edx               ; a = a % 65521
    xchg    eax, ebx               ; swap: eax=b, ebx=a
    xor     edx, edx
    div     ecx
    mov     eax, edx               ; b = b % 65521
    xchg    eax, ebx               ; swap back: eax=a, ebx=b
    pop     rcx
    inc     rsi
    dec     rcx
    jnz     .loop
.done:
    shl     ebx, 16
    or      eax, ebx
    pop     rbx
    ret
