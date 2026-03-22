;; =============================================================================
;; base64.inc — Base64 encode/decode (RFC 4648) — OS-agnostic
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; Pure byte manipulation — zero OS calls.
;; Ported from MASM asm/include/base64.inc to NASM 32-bit.
;; =============================================================================

section .data
    _b64chars db "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", 0
    _b64pad   db "=", 0

section .text

;; =============================================================================
;; b64_encode(esi=input, ecx=input_len, edi=output) → eax = output length
;; =============================================================================
global b64_encode
b64_encode:
    push    ebx
    push    ebp
    mov     ebp, ecx            ; save input length
    xor     edx, edx            ; output index

    test    ecx, ecx
    jz      .encode_done

.encode_loop:
    cmp     ecx, 0
    jle     .encode_done

    ;; Get up to 3 bytes
    movzx   eax, byte [esi]
    shl     eax, 16
    cmp     ecx, 1
    je      .one_byte
    movzx   ebx, byte [esi+1]
    shl     ebx, 8
    or      eax, ebx
    cmp     ecx, 2
    je      .two_bytes
    movzx   ebx, byte [esi+2]
    or      eax, ebx

    ;; 3 bytes → 4 base64 chars
    mov     ebx, eax
    shr     ebx, 18
    and     ebx, 0x3F
    mov     bl, [_b64chars + ebx]
    mov     [edi+edx], bl
    inc     edx

    mov     ebx, eax
    shr     ebx, 12
    and     ebx, 0x3F
    mov     bl, [_b64chars + ebx]
    mov     [edi+edx], bl
    inc     edx

    mov     ebx, eax
    shr     ebx, 6
    and     ebx, 0x3F
    mov     bl, [_b64chars + ebx]
    mov     [edi+edx], bl
    inc     edx

    mov     ebx, eax
    and     ebx, 0x3F
    mov     bl, [_b64chars + ebx]
    mov     [edi+edx], bl
    inc     edx

    add     esi, 3
    sub     ecx, 3
    jmp     .encode_loop

.two_bytes:
    mov     ebx, eax
    shr     ebx, 18
    and     ebx, 0x3F
    mov     bl, [_b64chars + ebx]
    mov     [edi+edx], bl
    inc     edx
    mov     ebx, eax
    shr     ebx, 12
    and     ebx, 0x3F
    mov     bl, [_b64chars + ebx]
    mov     [edi+edx], bl
    inc     edx
    mov     ebx, eax
    shr     ebx, 6
    and     ebx, 0x3F
    mov     bl, [_b64chars + ebx]
    mov     [edi+edx], bl
    inc     edx
    mov     byte [edi+edx], '='
    inc     edx
    jmp     .encode_done

.one_byte:
    mov     ebx, eax
    shr     ebx, 18
    and     ebx, 0x3F
    mov     bl, [_b64chars + ebx]
    mov     [edi+edx], bl
    inc     edx
    mov     ebx, eax
    shr     ebx, 12
    and     ebx, 0x3F
    mov     bl, [_b64chars + ebx]
    mov     [edi+edx], bl
    inc     edx
    mov     byte [edi+edx], '='
    inc     edx
    mov     byte [edi+edx], '='
    inc     edx

.encode_done:
    mov     eax, edx
    pop     ebp
    pop     ebx
    ret

;; =============================================================================
;; b64_decode_char(al) → al (6-bit value, 0xFF if invalid)
;; =============================================================================
b64_decode_char:
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

;; =============================================================================
;; b64_decode(esi=input, edi=output, ecx=max_out) → eax = output length
;; =============================================================================
global b64_decode
b64_decode:
    push    ebx
    push    ebp
    xor     edx, edx            ; output index
    mov     ebp, ecx            ; max output size

.decode_loop:
    movzx   eax, byte [esi]
    test    al, al
    jz      .decode_done
    cmp     al, '='
    je      .decode_done

    ;; Decode 4 chars → 3 bytes
    push    edx
    ;; char 1
    call    b64_decode_char
    movzx   ebx, al
    shl     ebx, 18
    inc     esi
    ;; char 2
    movzx   eax, byte [esi]
    call    b64_decode_char
    movzx   eax, al
    shl     eax, 12
    or      ebx, eax
    inc     esi
    ;; char 3
    movzx   eax, byte [esi]
    cmp     al, '='
    je      .decode_2
    test    al, al
    jz      .decode_2
    call    b64_decode_char
    movzx   eax, al
    shl     eax, 6
    or      ebx, eax
    inc     esi
    ;; char 4
    movzx   eax, byte [esi]
    cmp     al, '='
    je      .decode_3
    test    al, al
    jz      .decode_3
    call    b64_decode_char
    movzx   eax, al
    or      ebx, eax
    inc     esi

    pop     edx
    ;; Write 3 bytes
    mov     eax, ebx
    shr     eax, 16
    mov     [edi+edx], al
    inc     edx
    mov     eax, ebx
    shr     eax, 8
    mov     [edi+edx], al
    inc     edx
    mov     [edi+edx], bl
    inc     edx
    jmp     .decode_loop

.decode_3:
    inc     esi                 ; skip '='
    pop     edx
    mov     eax, ebx
    shr     eax, 16
    mov     [edi+edx], al
    inc     edx
    mov     eax, ebx
    shr     eax, 8
    mov     [edi+edx], al
    inc     edx
    jmp     .decode_done

.decode_2:
    inc     esi
    inc     esi                 ; skip '=='
    pop     edx
    mov     eax, ebx
    shr     eax, 16
    mov     [edi+edx], al
    inc     edx
    jmp     .decode_done

.decode_done:
    mov     eax, edx
    pop     ebp
    pop     ebx
    ret
