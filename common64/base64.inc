;; =============================================================================
;; base64.inc — Base64 encode/decode (RFC 4648) — OS-agnostic, x86_64
;; Part of pmash — lightweight remote agent
;; =============================================================================

section .data
    _b64chars db "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", 0

section .text

;; b64_encode(rdi=input, rsi=input_len, rdx=output) → rax = output length
global b64_encode
b64_encode:
    push    rbx
    push    r12
    mov     r12, rdx               ; output ptr
    mov     rcx, rsi               ; input_len
    mov     rsi, rdi               ; input ptr
    xor     edx, edx               ; output index

    test    rcx, rcx
    jz      .encode_done

.encode_loop:
    cmp     rcx, 0
    jle     .encode_done

    ;; Get up to 3 bytes
    movzx   eax, byte [rsi]
    shl     eax, 16
    cmp     rcx, 1
    je      .one_byte
    movzx   ebx, byte [rsi+1]
    shl     ebx, 8
    or      eax, ebx
    cmp     rcx, 2
    je      .two_bytes
    movzx   ebx, byte [rsi+2]
    or      eax, ebx

    ;; 3 bytes → 4 base64 chars
    mov     ebx, eax
    shr     ebx, 18
    and     ebx, 0x3F
    mov     bl, [_b64chars + rbx]
    mov     [r12+rdx], bl
    inc     edx

    mov     ebx, eax
    shr     ebx, 12
    and     ebx, 0x3F
    mov     bl, [_b64chars + rbx]
    mov     [r12+rdx], bl
    inc     edx

    mov     ebx, eax
    shr     ebx, 6
    and     ebx, 0x3F
    mov     bl, [_b64chars + rbx]
    mov     [r12+rdx], bl
    inc     edx

    mov     ebx, eax
    and     ebx, 0x3F
    mov     bl, [_b64chars + rbx]
    mov     [r12+rdx], bl
    inc     edx

    add     rsi, 3
    sub     rcx, 3
    jmp     .encode_loop

.two_bytes:
    mov     ebx, eax
    shr     ebx, 18
    and     ebx, 0x3F
    mov     bl, [_b64chars + rbx]
    mov     [r12+rdx], bl
    inc     edx
    mov     ebx, eax
    shr     ebx, 12
    and     ebx, 0x3F
    mov     bl, [_b64chars + rbx]
    mov     [r12+rdx], bl
    inc     edx
    mov     ebx, eax
    shr     ebx, 6
    and     ebx, 0x3F
    mov     bl, [_b64chars + rbx]
    mov     [r12+rdx], bl
    inc     edx
    mov     byte [r12+rdx], '='
    inc     edx
    jmp     .encode_done

.one_byte:
    mov     ebx, eax
    shr     ebx, 18
    and     ebx, 0x3F
    mov     bl, [_b64chars + rbx]
    mov     [r12+rdx], bl
    inc     edx
    mov     ebx, eax
    shr     ebx, 12
    and     ebx, 0x3F
    mov     bl, [_b64chars + rbx]
    mov     [r12+rdx], bl
    inc     edx
    mov     byte [r12+rdx], '='
    inc     edx
    mov     byte [r12+rdx], '='
    inc     edx

.encode_done:
    mov     eax, edx
    pop     r12
    pop     rbx
    ret

;; b64_decode_char(dil) → al (6-bit value, 0xFF if invalid)
b64_decode_char:
    movzx   eax, dil
    cmp     al, 'A'
    jb      .dc_check_lower
    cmp     al, 'Z'
    ja      .dc_check_lower
    sub     al, 'A'
    ret
.dc_check_lower:
    cmp     al, 'a'
    jb      .dc_check_digit
    cmp     al, 'z'
    ja      .dc_check_digit
    sub     al, 'a'
    add     al, 26
    ret
.dc_check_digit:
    cmp     al, '0'
    jb      .dc_check_plus
    cmp     al, '9'
    ja      .dc_check_plus
    sub     al, '0'
    add     al, 52
    ret
.dc_check_plus:
    cmp     al, '+'
    jne     .dc_check_slash
    mov     al, 62
    ret
.dc_check_slash:
    cmp     al, '/'
    jne     .dc_invalid
    mov     al, 63
    ret
.dc_invalid:
    mov     al, 0xFF
    ret

;; b64_decode(rdi=input, rsi=output, rdx=max_out) → rax = output length
global b64_decode
b64_decode:
    push    rbx
    push    r12
    push    r13
    mov     r12, rdi               ; input
    mov     r13, rsi               ; output
    xor     edx, edx               ; output index

.decode_loop:
    movzx   eax, byte [r12]
    test    al, al
    jz      .decode_done
    cmp     al, '='
    je      .decode_done

    ;; Decode 4 chars → 3 bytes
    push    rdx
    ;; char 1
    mov     dil, [r12]
    call    b64_decode_char
    movzx   ebx, al
    shl     ebx, 18
    inc     r12
    ;; char 2
    mov     dil, [r12]
    call    b64_decode_char
    movzx   eax, al
    shl     eax, 12
    or      ebx, eax
    inc     r12
    ;; char 3
    movzx   eax, byte [r12]
    cmp     al, '='
    je      .decode_2
    test    al, al
    jz      .decode_2
    mov     dil, al
    call    b64_decode_char
    movzx   eax, al
    shl     eax, 6
    or      ebx, eax
    inc     r12
    ;; char 4
    movzx   eax, byte [r12]
    cmp     al, '='
    je      .decode_3
    test    al, al
    jz      .decode_3
    mov     dil, al
    call    b64_decode_char
    movzx   eax, al
    or      ebx, eax
    inc     r12

    pop     rdx
    ;; Write 3 bytes
    mov     eax, ebx
    shr     eax, 16
    mov     [r13+rdx], al
    inc     edx
    mov     eax, ebx
    shr     eax, 8
    mov     [r13+rdx], al
    inc     edx
    mov     [r13+rdx], bl
    inc     edx
    jmp     .decode_loop

.decode_3:
    inc     r12
    pop     rdx
    mov     eax, ebx
    shr     eax, 16
    mov     [r13+rdx], al
    inc     edx
    mov     eax, ebx
    shr     eax, 8
    mov     [r13+rdx], al
    inc     edx
    jmp     .decode_done

.decode_2:
    inc     r12
    inc     r12
    pop     rdx
    mov     eax, ebx
    shr     eax, 16
    mov     [r13+rdx], al
    inc     edx
    jmp     .decode_done

.decode_done:
    mov     eax, edx
    pop     r13
    pop     r12
    pop     rbx
    ret
