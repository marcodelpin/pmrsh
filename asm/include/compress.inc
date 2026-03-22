;; =============================================================================
;; compress.inc — Payload compression using Windows RtlCompressBuffer
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; Uses ntdll RtlCompressBuffer/RtlDecompressBuffer (always available).
;; LZNT1 format (COMPRESSION_FORMAT_LZNT1 = 2) — fast, good for small payloads.
;; Compress flag byte prepended: 0x00=raw, 0x02=LZNT1
;; =============================================================================

;; ---- ntdll API ----
RtlCompressBuffer       PROTO :WORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlDecompressBuffer     PROTO :WORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
RtlGetCompressionWorkSpaceSize PROTO :WORD, :DWORD, :DWORD

COMPRESSION_FORMAT_LZNT1    equ 2
COMPRESSION_ENGINE_STANDARD equ 0000h
COMPRESSION_ENGINE_MAXIMUM  equ 0100h

;; Minimum payload size to bother compressing (below this, overhead > savings)
COMPRESS_THRESHOLD  equ 512

IFNDEF _GLOBALALLOC_DEFINED
_GLOBALALLOC_DEFINED equ 1
GlobalAlloc     PROTO :DWORD, :DWORD
GlobalFree      PROTO :DWORD
ENDIF
IFNDEF _RTLCOPYMEMORY_DEFINED
_RTLCOPYMEMORY_DEFINED equ 1
RtlMoveMemory   PROTO :DWORD, :DWORD, :DWORD
ENDIF

.data?
    _compressWsSize DWORD ?
    _compressFragSize DWORD ?
    _pCompressWs    DWORD ?         ; workspace buffer (allocated once)

.code

;; =============================================================================
;; CompressInit — Allocate compression workspace (call once at startup)
;; Returns: 0 = success
;; =============================================================================
CompressInit PROC
    invoke  RtlGetCompressionWorkSpaceSize, \
            COMPRESSION_FORMAT_LZNT1 or COMPRESSION_ENGINE_STANDARD, \
            ADDR _compressWsSize, ADDR _compressFragSize
    test    eax, eax
    jnz     @ci_fail
    invoke  GlobalAlloc, 0, _compressWsSize
    test    eax, eax
    jz      @ci_fail
    mov     _pCompressWs, eax
    xor     eax, eax
    ret
@ci_fail:
    mov     _pCompressWs, 0
    mov     eax, -1
    ret
CompressInit ENDP

;; =============================================================================
;; CompressPayload — Compress buffer if beneficial
;; Args: pIn (input data), cbIn (input size)
;;       ppOut (output: compressed data with flag byte), pcbOut (output: size)
;; Returns: 0 = success. Caller must GlobalFree *ppOut.
;; Output format: [flag_byte][data]
;;   flag=0x00: raw (data is uncompressed, size = cbIn)
;;   flag=0x02: LZNT1 (data is compressed)
;; =============================================================================
CompressPayload PROC uses ebx esi edi \
    pIn:DWORD, cbIn:DWORD, ppOut:DWORD, pcbOut:DWORD

    LOCAL   pCompBuf:DWORD
    LOCAL   cbComp:DWORD
    LOCAL   cbOutBuf:DWORD
    LOCAL   pCompDst:DWORD
    LOCAL   cbCompDst:DWORD

    ;; Below threshold or no workspace → send raw
    cmp     cbIn, COMPRESS_THRESHOLD
    jb      @cp_raw
    cmp     _pCompressWs, 0
    je      @cp_raw

    ;; Allocate output: worst case = input size + 1 (flag byte)
    mov     eax, cbIn
    add     eax, cbIn               ; 2x input for worst case
    add     eax, 1                  ; flag byte
    mov     cbOutBuf, eax
    invoke  GlobalAlloc, 0, cbOutBuf
    test    eax, eax
    jz      @cp_raw
    mov     pCompBuf, eax

    ;; Compress
    mov     eax, pCompBuf
    inc     eax                     ; skip flag byte, compress into buf+1
    mov     pCompDst, eax
    mov     eax, cbOutBuf
    dec     eax
    mov     cbCompDst, eax
    invoke  RtlCompressBuffer, \
            COMPRESSION_FORMAT_LZNT1 or COMPRESSION_ENGINE_STANDARD, \
            pIn, cbIn, pCompDst, cbCompDst, 4096, ADDR cbComp, _pCompressWs
    test    eax, eax
    jnz     @cp_comp_fail

    ;; Check if compression saved space (at least 10%)
    mov     eax, cbIn
    mov     ecx, 10
    xor     edx, edx
    div     ecx                     ; eax = cbIn / 10
    mov     ecx, cbIn
    sub     ecx, eax                ; ecx = cbIn * 0.9
    cmp     cbComp, ecx
    jge     @cp_comp_fail           ; not worth it

    ;; Compressed successfully — set flag byte
    mov     edi, pCompBuf
    mov     byte ptr [edi], COMPRESSION_FORMAT_LZNT1
    mov     eax, cbComp
    inc     eax                     ; +1 for flag byte
    ;; Return compressed buffer
    mov     edx, ppOut
    mov     ecx, pCompBuf
    mov     [edx], ecx
    mov     edx, pcbOut
    mov     [edx], eax
    xor     eax, eax
    ret

@cp_comp_fail:
    invoke  GlobalFree, pCompBuf

@cp_raw:
    ;; Send raw: [0x00][original data]
    mov     eax, cbIn
    inc     eax                     ; +1 for flag byte
    invoke  GlobalAlloc, 0, eax
    test    eax, eax
    jz      @cp_fail
    mov     pCompBuf, eax
    mov     byte ptr [eax], COMPRESS_RAW
    lea     edi, [eax + 1]
    invoke  RtlMoveMemory, edi, pIn, cbIn
    mov     eax, cbIn
    inc     eax
    mov     edx, ppOut
    mov     ecx, pCompBuf
    mov     [edx], ecx
    mov     edx, pcbOut
    mov     [edx], eax
    xor     eax, eax
    ret

@cp_fail:
    mov     eax, -1
    ret
CompressPayload ENDP

;; =============================================================================
;; DecompressPayload — Decompress buffer based on flag byte
;; Args: pIn (input: [flag][data]), cbIn (total input size)
;;       ppOut (output: decompressed data), pcbOut (output: size)
;; Returns: 0 = success. Caller must GlobalFree *ppOut.
;; =============================================================================
DecompressPayload PROC uses ebx esi edi \
    pIn:DWORD, cbIn:DWORD, ppOut:DWORD, pcbOut:DWORD

    LOCAL   pDecBuf:DWORD
    LOCAL   cbDec:DWORD
    LOCAL   pCompSrc:DWORD
    LOCAL   cbCompSrc:DWORD
    LOCAL   cbDecBuf:DWORD

    cmp     cbIn, 1
    jb      @dp_fail

    mov     esi, pIn
    movzx   eax, byte ptr [esi]

    cmp     al, COMPRESS_RAW
    je      @dp_raw
    cmp     al, COMPRESSION_FORMAT_LZNT1
    je      @dp_lznt1
    ;; Unknown format — treat as raw (backward compat)
    jmp     @dp_raw

@dp_raw:
    ;; Raw: copy data after flag byte
    mov     eax, cbIn
    dec     eax                     ; remove flag byte
    mov     cbDec, eax
    invoke  GlobalAlloc, 0, cbDec
    test    eax, eax
    jz      @dp_fail
    mov     pDecBuf, eax
    mov     esi, pIn
    inc     esi                     ; skip flag byte
    invoke  RtlMoveMemory, pDecBuf, esi, cbDec
    mov     edx, ppOut
    mov     eax, pDecBuf
    mov     [edx], eax
    mov     edx, pcbOut
    mov     eax, cbDec
    mov     [edx], eax
    xor     eax, eax
    ret

@dp_lznt1:
    ;; LZNT1 compressed — allocate generous output buffer
    mov     eax, cbIn
    shl     eax, 3                  ; 8x input as estimate
    cmp     eax, 65536
    jge     @dp_alloc
    mov     eax, 65536              ; minimum 64KB
@dp_alloc:
    invoke  GlobalAlloc, 0, eax
    test    eax, eax
    jz      @dp_fail
    mov     pDecBuf, eax

    ;; Decompress — use locals to avoid register clobber in invoke
    mov     eax, pIn
    inc     eax
    mov     pCompSrc, eax           ; skip flag byte
    mov     eax, cbIn
    dec     eax
    mov     cbCompSrc, eax          ; compressed data size
    mov     eax, cbIn
    shl     eax, 3
    cmp     eax, 65536
    jge     @dp_decomp
    mov     eax, 65536
@dp_decomp:
    mov     cbDecBuf, eax
    invoke  RtlDecompressBuffer, COMPRESSION_FORMAT_LZNT1, \
            pDecBuf, cbDecBuf, pCompSrc, cbCompSrc, ADDR cbDec
    test    eax, eax
    jnz     @dp_free

    mov     edx, ppOut
    mov     eax, pDecBuf
    mov     [edx], eax
    mov     edx, pcbOut
    mov     eax, cbDec
    mov     [edx], eax
    xor     eax, eax
    ret

@dp_free:
    invoke  GlobalFree, pDecBuf
@dp_fail:
    mov     eax, -1
    ret
DecompressPayload ENDP
