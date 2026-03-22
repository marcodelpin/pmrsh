;; =============================================================================
;; hash.inc — Adler32 + MD5 hashing for delta sync
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; Adler32: rolling hash for block matching (fast, 4 bytes)
;; MD5: strong hash for block verification (16 bytes)
;; Both needed for rsync-like delta transfer
;; =============================================================================

.code

;; =============================================================================
;; Adler32 — Compute Adler-32 checksum
;; Args: lpData, nLen
;; Returns: 32-bit checksum in eax
;; =============================================================================
Adler32 PROC uses esi lpData:DWORD, nLen:DWORD
    mov     esi, lpData
    mov     ecx, nLen
    mov     eax, 1              ; a = 1
    xor     edx, edx            ; b = 0

@a32_loop:
    test    ecx, ecx
    jz      @a32_done
    movzx   ebx, byte ptr [esi]
    add     eax, ebx            ; a += byte
    ;; a %= 65521
    push    ecx
    push    edx
    xor     edx, edx
    mov     ecx, 65521
    div     ecx
    mov     eax, edx            ; a = a % 65521
    pop     edx
    add     edx, eax            ; b += a
    ;; b %= 65521
    push    eax
    mov     eax, edx
    xor     edx, edx
    mov     ecx, 65521
    div     ecx
    mov     ebx, edx            ; b = b % 65521
    pop     eax
    mov     edx, ebx
    pop     ecx

    inc     esi
    dec     ecx
    jmp     @a32_loop

@a32_done:
    ;; result = (b << 16) | a
    shl     edx, 16
    or      eax, edx
    ret
Adler32 ENDP

;; =============================================================================
;; MD5 — Compute MD5 hash using BCrypt (reuses crypto.inc CNG provider)
;; Args: lpData, nLen, lpHashOut (16-byte output buffer)
;; Returns: 0 = success, -1 = error
;; =============================================================================
MD5Init PROTO
MD5Hash PROTO :DWORD, :DWORD, :DWORD

.data
    _szAlgMD5   dw 'M','D','5',0

.data?
    _hAlgMD5    DWORD ?
    _md5Inited  DWORD ?

.code

MD5Init PROC
    cmp     _md5Inited, 1
    je      @md5i_ok
    invoke  BCryptOpenAlgorithmProvider, ADDR _hAlgMD5, ADDR _szAlgMD5, NULL, 0
    test    eax, eax
    jnz     @md5i_fail
    mov     _md5Inited, 1
@md5i_ok:
    xor     eax, eax
    ret
@md5i_fail:
    mov     eax, -1
    ret
MD5Init ENDP

MD5Hash PROC lpData:DWORD, nLen:DWORD, lpHashOut:DWORD
    LOCAL   hHash:DWORD

    invoke  MD5Init
    test    eax, eax
    jnz     @md5h_fail

    invoke  BCryptCreateHash, _hAlgMD5, ADDR hHash, NULL, 0, NULL, 0, 0
    test    eax, eax
    jnz     @md5h_fail

    invoke  BCryptHashData, hHash, lpData, nLen, 0
    test    eax, eax
    jnz     @md5h_destroy

    invoke  BCryptFinishHash, hHash, lpHashOut, 16, 0
    push    eax
    invoke  BCryptDestroyHash, hHash
    pop     eax
    test    eax, eax
    jnz     @md5h_fail
    xor     eax, eax
    ret

@md5h_destroy:
    invoke  BCryptDestroyHash, hHash
@md5h_fail:
    mov     eax, -1
    ret
MD5Hash ENDP
