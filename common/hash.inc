;; =============================================================================
;; hash.inc — Adler32 checksum (OS-agnostic, pure math)
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; MD5 is OS-specific (BCrypt on Windows, raw implementation needed for Linux)
;; For now, only Adler32 is in common. MD5 will be in os/md5_*.inc
;; =============================================================================

section .text

;; =============================================================================
;; adler32(esi=data, ecx=len) → eax = checksum
;; =============================================================================
global adler32
adler32:
    push    ebx
    push    edx
    mov     eax, 1              ; a = 1
    xor     ebx, ebx            ; b = 0
    test    ecx, ecx
    jz      .done
.loop:
    movzx   edx, byte [esi]
    add     eax, edx            ; a += byte
    add     ebx, eax            ; b += a
    ;; Modulo 65521 (Adler32 prime)
    push    ecx
    mov     ecx, 65521
    xor     edx, edx
    div     ecx                 ; eax = a % 65521
    mov     eax, edx            ; remainder
    xchg    eax, ebx            ; swap: eax=b, ebx=a
    xor     edx, edx
    div     ecx
    mov     eax, edx            ; b = b % 65521
    xchg    eax, ebx            ; swap back: eax=a, ebx=b
    pop     ecx
    inc     esi
    dec     ecx
    jnz     .loop
.done:
    ;; Result: (b << 16) | a
    shl     ebx, 16
    or      eax, ebx
    pop     edx
    pop     ebx
    ret
