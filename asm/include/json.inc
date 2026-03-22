;; =============================================================================
;; json.inc — Minimal JSON builder/parser for mrsh wire protocol
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; Provides: JsonBuild* (output), JsonFind (input parsing)
;; No full parser — just enough for mrsh protocol messages
;; =============================================================================

wsprintfA   PROTO C :DWORD, :DWORD, :VARARG
lstrcpyA    PROTO :DWORD, :DWORD
lstrcatA    PROTO :DWORD, :DWORD
lstrlenA    PROTO :DWORD

.data
    ;; JSON templates for request/response
    _jFmtExec   db '{"type":"exec","command":"%s"}', 0
    _jFmtLs     db '{"type":"ls","path":"%s"}', 0
    _jFmtLsAll  db '{"type":"ls"}', 0
    _jFmtRead   db '{"type":"read","path":"%s"}', 0
    _jFmtWrite  db '{"type":"write","path":"%s","content":"%s"}', 0
    _jFmtPing   db '{"type":"ping"}', 0
    _jFmtInfo   db '{"type":"info"}', 0
    _jFmtShot   db '{"type":"screenshot"}', 0
    _jFmtUpdate db '{"type":"self-update","path":"%s"}', 0

    ;; Auth templates
    _jFmtAuth   db '{"type":"auth","public_key":"%s","version":"pmash 0.1.0","caps":[]}', 0
    _jFmtSig    db '{"signature":"%s"}', 0

    ;; Response templates (server)
    _jFmtResp   db '{"success":true,"output":"%s"}', 0
    _jFmtRespBin db '{"success":true,"output":"%s","binary":true}', 0
    _jFmtRespErr db '{"success":false,"error":"%s"}', 0
    _jFmtPong   db '{"success":true,"output":"pong"}', 0
    _jFmtAuthOk db '{"success":true,"version":"pmash 0.1.0","caps":[]}', 0
    _jFmtAuthFail db '{"success":false,"error":"%s"}', 0
    _jFmtChallenge db '{"challenge":"%s"}', 0

.code

;; =============================================================================
;; JsonFind — Find value for a key in JSON string (simple, no nesting)
;; Args: lpJson (input), lpKey (key name without quotes), lpOut (output buffer), nOutSize
;; Returns: length of value, 0 if not found
;; Handles: "key":"value" and "key":true/false/number
;; =============================================================================
JsonFind PROC uses ebx esi edi lpJson:DWORD, lpKey:DWORD, lpOut:DWORD, nOutSize:DWORD
    LOCAL   keyLen:DWORD

    invoke  lstrlenA, lpKey
    mov     keyLen, eax
    mov     esi, lpJson

@jf_scan:
    mov     al, byte ptr [esi]
    cmp     al, 0
    je      @jf_notfound
    cmp     al, '"'
    jne     @jf_next
    ;; Found a quote — check if key matches
    inc     esi
    mov     edi, lpKey
    mov     ecx, keyLen
@jf_cmp:
    cmp     ecx, 0
    je      @jf_key_end
    mov     al, byte ptr [esi]
    cmp     al, byte ptr [edi]
    jne     @jf_skip_str
    inc     esi
    inc     edi
    dec     ecx
    jmp     @jf_cmp
@jf_key_end:
    ;; Key matched — check for closing quote + colon
    cmp     byte ptr [esi], '"'
    jne     @jf_skip_str
    inc     esi                     ; skip closing quote
    ;; Skip whitespace
@jf_ws1:
    cmp     byte ptr [esi], ' '
    jne     @jf_colon
    inc     esi
    jmp     @jf_ws1
@jf_colon:
    cmp     byte ptr [esi], ':'
    jne     @jf_next
    inc     esi
    ;; Skip whitespace after colon
@jf_ws2:
    cmp     byte ptr [esi], ' '
    jne     @jf_value
    inc     esi
    jmp     @jf_ws2

@jf_value:
    ;; Value starts here — could be "string", number, true, false, null, [array]
    mov     edi, lpOut
    mov     ebx, 0                  ; output length
    cmp     byte ptr [esi], '"'
    je      @jf_string
    ;; Non-string value (number, bool, null, array, object)
@jf_raw:
    mov     al, byte ptr [esi]
    cmp     al, 0
    je      @jf_raw_done
    cmp     al, ','
    je      @jf_raw_done
    cmp     al, '}'
    je      @jf_raw_done
    cmp     al, ']'
    je      @jf_raw_done
    cmp     ebx, nOutSize
    jge     @jf_raw_done
    mov     byte ptr [edi], al
    inc     esi
    inc     edi
    inc     ebx
    jmp     @jf_raw
@jf_raw_done:
    mov     byte ptr [edi], 0
    mov     eax, ebx
    ret

@jf_string:
    inc     esi                     ; skip opening quote
@jf_str_loop:
    mov     al, byte ptr [esi]
    cmp     al, 0
    je      @jf_str_done
    cmp     al, '"'
    je      @jf_str_done
    cmp     al, '\'
    jne     @jf_str_copy
    ;; Escape sequence — copy next char
    inc     esi
    mov     al, byte ptr [esi]
    cmp     al, 0
    je      @jf_str_done
@jf_str_copy:
    cmp     ebx, nOutSize
    jge     @jf_str_done
    mov     byte ptr [edi], al
    inc     esi
    inc     edi
    inc     ebx
    jmp     @jf_str_loop
@jf_str_done:
    mov     byte ptr [edi], 0
    mov     eax, ebx
    ret

@jf_skip_str:
    ;; Skip to end of this string
    mov     al, byte ptr [esi]
    cmp     al, 0
    je      @jf_notfound
    cmp     al, '"'
    je      @jf_skip_end
    inc     esi
    jmp     @jf_skip_str
@jf_skip_end:
    inc     esi
@jf_next:
    inc     esi
    jmp     @jf_scan

@jf_notfound:
    xor     eax, eax
    ret
JsonFind ENDP
