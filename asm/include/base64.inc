;; =============================================================================
;; base64.inc — Base64 encode/decode (RFC 4648)
;; Part of pmash — lightweight remote agent
;; =============================================================================

.data
    _b64chars db "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    _b64pad   db "=", 0

.code

;; =============================================================================
;; Base64Encode — Encode binary to base64 string
;; Args: lpIn (binary), nInLen, lpOut (output string buffer)
;; Returns: length of base64 string in eax
;; Output buffer must be at least ((nInLen+2)/3)*4 + 1 bytes
;; =============================================================================
Base64Encode PROC uses ebx esi edi lpIn:DWORD, nInLen:DWORD, lpOut:DWORD
    mov     esi, lpIn
    mov     edi, lpOut
    mov     ecx, nInLen
    xor     ebx, ebx                ; output count

@b64e_loop:
    cmp     ecx, 3
    jl      @b64e_tail

    ;; Read 3 bytes → 4 base64 chars
    movzx   eax, byte ptr [esi]
    shl     eax, 16
    movzx   edx, byte ptr [esi + 1]
    shl     edx, 8
    or      eax, edx
    movzx   edx, byte ptr [esi + 2]
    or      eax, edx
    ;; eax = 24-bit value

    mov     edx, eax
    shr     edx, 18
    and     edx, 3Fh
    mov     dl, byte ptr [_b64chars + edx]
    mov     byte ptr [edi], dl

    mov     edx, eax
    shr     edx, 12
    and     edx, 3Fh
    mov     dl, byte ptr [_b64chars + edx]
    mov     byte ptr [edi + 1], dl

    mov     edx, eax
    shr     edx, 6
    and     edx, 3Fh
    mov     dl, byte ptr [_b64chars + edx]
    mov     byte ptr [edi + 2], dl

    mov     edx, eax
    and     edx, 3Fh
    mov     dl, byte ptr [_b64chars + edx]
    mov     byte ptr [edi + 3], dl

    add     esi, 3
    add     edi, 4
    add     ebx, 4
    sub     ecx, 3
    jmp     @b64e_loop

@b64e_tail:
    cmp     ecx, 0
    je      @b64e_done

    cmp     ecx, 1
    je      @b64e_1byte

    ;; 2 remaining bytes
    movzx   eax, byte ptr [esi]
    shl     eax, 16
    movzx   edx, byte ptr [esi + 1]
    shl     edx, 8
    or      eax, edx

    mov     edx, eax
    shr     edx, 18
    and     edx, 3Fh
    mov     dl, byte ptr [_b64chars + edx]
    mov     byte ptr [edi], dl

    mov     edx, eax
    shr     edx, 12
    and     edx, 3Fh
    mov     dl, byte ptr [_b64chars + edx]
    mov     byte ptr [edi + 1], dl

    mov     edx, eax
    shr     edx, 6
    and     edx, 3Fh
    mov     dl, byte ptr [_b64chars + edx]
    mov     byte ptr [edi + 2], dl

    mov     byte ptr [edi + 3], '='
    add     edi, 4
    add     ebx, 4
    jmp     @b64e_done

@b64e_1byte:
    movzx   eax, byte ptr [esi]
    shl     eax, 16

    mov     edx, eax
    shr     edx, 18
    and     edx, 3Fh
    mov     dl, byte ptr [_b64chars + edx]
    mov     byte ptr [edi], dl

    mov     edx, eax
    shr     edx, 12
    and     edx, 3Fh
    mov     dl, byte ptr [_b64chars + edx]
    mov     byte ptr [edi + 1], dl

    mov     byte ptr [edi + 2], '='
    mov     byte ptr [edi + 3], '='
    add     edi, 4
    add     ebx, 4

@b64e_done:
    mov     byte ptr [edi], 0       ; null terminate
    mov     eax, ebx
    ret
Base64Encode ENDP

;; =============================================================================
;; Base64Decode — Decode base64 string to binary
;; Args: lpIn (base64 string), lpOut (binary output), nOutSize (max)
;; Returns: number of decoded bytes in eax, -1 on error
;; =============================================================================
Base64Decode PROC uses ebx esi edi lpIn:DWORD, lpOut:DWORD, nOutSize:DWORD
    LOCAL   val:DWORD

    mov     esi, lpIn
    mov     edi, lpOut
    xor     ebx, ebx                ; output count

@b64d_loop:
    ;; Read 4 base64 chars → 3 bytes
    mov     val, 0
    xor     ecx, ecx                ; char count in this group

@b64d_group:
    cmp     ecx, 4
    jge     @b64d_emit

    movzx   eax, byte ptr [esi]
    cmp     al, 0
    je      @b64d_emit
    cmp     al, '='
    je      @b64d_pad
    inc     esi

    ;; Decode single char to 6-bit value
    cmp     al, 'A'
    jb      @b64d_lower
    cmp     al, 'Z'
    ja      @b64d_lower
    sub     al, 'A'
    jmp     @b64d_shift
@b64d_lower:
    cmp     al, 'a'
    jb      @b64d_digit
    cmp     al, 'z'
    ja      @b64d_digit
    sub     al, 'a'
    add     al, 26
    jmp     @b64d_shift
@b64d_digit:
    cmp     al, '0'
    jb      @b64d_plus
    cmp     al, '9'
    ja      @b64d_plus
    sub     al, '0'
    add     al, 52
    jmp     @b64d_shift
@b64d_plus:
    cmp     al, '+'
    jne     @b64d_slash
    mov     al, 62
    jmp     @b64d_shift
@b64d_slash:
    cmp     al, '/'
    jne     @b64d_skip          ; skip whitespace/invalid
    mov     al, 63

@b64d_shift:
    movzx   edx, al
    shl     val, 6
    or      val, edx
    inc     ecx
    jmp     @b64d_group

@b64d_pad:
    ;; Padding — shift and count
    shl     val, 6
    inc     ecx
    inc     esi
    jmp     @b64d_group

@b64d_skip:
    jmp     @b64d_group

@b64d_emit:
    cmp     ecx, 0
    je      @b64d_done

    ;; Emit bytes based on how many chars we got
    cmp     ecx, 4
    jl      @b64d_partial

    ;; Full 4-char group → 3 bytes (but check padding)
    mov     eax, val
    cmp     ebx, nOutSize
    jge     @b64d_done
    mov     edx, eax
    shr     edx, 16
    and     edx, 0FFh
    mov     byte ptr [edi], dl
    inc     edi
    inc     ebx

    ;; Check if 3rd char was pad
    mov     dl, byte ptr [esi - 2]
    cmp     dl, '='
    je      @b64d_done

    cmp     ebx, nOutSize
    jge     @b64d_done
    mov     edx, eax
    shr     edx, 8
    and     edx, 0FFh
    mov     byte ptr [edi], dl
    inc     edi
    inc     ebx

    ;; Check if 4th char was pad
    mov     dl, byte ptr [esi - 1]
    cmp     dl, '='
    je      @b64d_done

    cmp     ebx, nOutSize
    jge     @b64d_done
    and     eax, 0FFh
    mov     byte ptr [edi], al
    inc     edi
    inc     ebx
    jmp     @b64d_loop

@b64d_partial:
    ;; Less than 4 chars — emit what we can
    cmp     ecx, 2
    jl      @b64d_done
    mov     eax, val
    shl     eax, 6                  ; align
    shr     eax, 16
    cmp     ebx, nOutSize
    jge     @b64d_done
    mov     byte ptr [edi], al
    inc     ebx

@b64d_done:
    mov     eax, ebx
    ret
Base64Decode ENDP
