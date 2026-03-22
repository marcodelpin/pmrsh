;; =============================================================================
;; protobuf.inc — Minimal protobuf encoder/decoder for hbbs rendezvous
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; Only supports: varint, length-delimited (string/bytes), int32 fields.
;; No reflection, no schema — hardcoded for rdv.proto messages.
;; =============================================================================

IFNDEF _GLOBALALLOC_DEFINED
_GLOBALALLOC_DEFINED equ 1
GlobalAlloc     PROTO :DWORD, :DWORD
GlobalFree      PROTO :DWORD
ENDIF
IFNDEF _RTLZEROMEMORY_DEFINED
_RTLZEROMEMORY_DEFINED equ 1
RtlZeroMemory   PROTO :DWORD, :DWORD
ENDIF

lstrlenA    PROTO :DWORD
IFNDEF _RTLCOPYMEMORY_DEFINED
_RTLCOPYMEMORY_DEFINED equ 1
RtlMoveMemory   PROTO :DWORD, :DWORD, :DWORD
ENDIF

;; Wire types
PB_VARINT       equ 0
PB_LEN          equ 2      ; length-delimited (string, bytes, submessage)

;; Make tag: (field_number << 3) | wire_type
PB_TAG MACRO fnum, wtype
    EXITM <((fnum SHL 3) OR wtype)>
ENDM

.code

;; =============================================================================
;; PbEncodeVarint — Encode a varint at pBuf, return bytes written in eax
;; Args: pBuf (write position), value (32-bit unsigned)
;; =============================================================================
PbEncodeVarint PROC pBuf:DWORD, dwValue:DWORD
    mov     edx, pBuf
    mov     eax, dwValue
@pev_loop:
    mov     ecx, eax
    and     cl, 7Fh                 ; low 7 bits
    shr     eax, 7
    test    eax, eax
    jz      @pev_last
    or      cl, 80h                 ; set continuation bit
    mov     [edx], cl
    inc     edx
    jmp     @pev_loop
@pev_last:
    mov     [edx], cl
    inc     edx
    sub     edx, pBuf
    mov     eax, edx                ; bytes written
    ret
PbEncodeVarint ENDP

;; =============================================================================
;; PbDecodeVarint — Decode a varint from pBuf, return value in eax, advance *ppBuf
;; Args: ppBuf (ptr to read position ptr), pValue (output)
;; Returns: 0=success, updates *ppBuf past the varint
;; =============================================================================
PbDecodeVarint PROC ppBuf:DWORD, pValue:DWORD
    mov     edx, ppBuf
    mov     esi, [edx]              ; esi = current read ptr
    xor     eax, eax                ; accumulator
    xor     ecx, ecx                ; shift counter
@pdv_loop:
    movzx   ebx, byte ptr [esi]
    inc     esi
    push    ebx
    and     ebx, 7Fh
    shl     ebx, cl
    or      eax, ebx
    add     cl, 7
    pop     ebx
    test    bl, 80h
    jnz     @pdv_loop
    ;; Store value and update pointer
    mov     edx, pValue
    mov     [edx], eax
    mov     edx, ppBuf
    mov     [edx], esi
    xor     eax, eax
    ret
PbDecodeVarint ENDP

;; =============================================================================
;; PbWriteString — Write a string field: tag + varint(len) + bytes
;; Args: pBuf, fieldNum, lpStr
;; Returns: bytes written in eax
;; =============================================================================
PbWriteString PROC uses esi edi pBuf:DWORD, dwFieldNum:DWORD, lpStr:DWORD
    LOCAL   cbStr:DWORD

    cmp     lpStr, 0
    je      @pws_zero
    invoke  lstrlenA, lpStr
    mov     cbStr, eax
    cmp     eax, 0
    je      @pws_zero               ; skip empty strings (proto3 default)

    mov     edi, pBuf
    ;; Write tag: (fieldNum << 3) | PB_LEN
    mov     eax, dwFieldNum
    shl     eax, 3
    or      eax, PB_LEN
    invoke  PbEncodeVarint, edi, eax
    add     edi, eax

    ;; Write length
    invoke  PbEncodeVarint, edi, cbStr
    add     edi, eax

    ;; Write string bytes
    invoke  RtlMoveMemory, edi, lpStr, cbStr
    add     edi, cbStr

    sub     edi, pBuf
    mov     eax, edi                ; total bytes written
    ret

@pws_zero:
    xor     eax, eax
    ret
PbWriteString ENDP

;; =============================================================================
;; PbWriteBytes — Write a bytes field: tag + varint(len) + raw bytes
;; =============================================================================
PbWriteBytes PROC uses esi edi pBuf:DWORD, dwFieldNum:DWORD, lpData:DWORD, cbData:DWORD
    cmp     cbData, 0
    je      @pwb_zero

    mov     edi, pBuf
    mov     eax, dwFieldNum
    shl     eax, 3
    or      eax, PB_LEN
    invoke  PbEncodeVarint, edi, eax
    add     edi, eax
    invoke  PbEncodeVarint, edi, cbData
    add     edi, eax
    invoke  RtlMoveMemory, edi, lpData, cbData
    add     edi, cbData

    sub     edi, pBuf
    mov     eax, edi
    ret
@pwb_zero:
    xor     eax, eax
    ret
PbWriteBytes ENDP

;; =============================================================================
;; PbWriteInt32 — Write an int32 field: tag + varint(value)
;; =============================================================================
PbWriteInt32 PROC pBuf:DWORD, dwFieldNum:DWORD, dwValue:DWORD
    cmp     dwValue, 0
    je      @pwi_zero               ; proto3: skip default values

    mov     edi, pBuf
    mov     eax, dwFieldNum
    shl     eax, 3
    or      eax, PB_VARINT
    invoke  PbEncodeVarint, edi, eax
    add     edi, eax
    invoke  PbEncodeVarint, edi, dwValue
    add     edi, eax

    sub     edi, pBuf
    mov     eax, edi
    ret
@pwi_zero:
    xor     eax, eax
    ret
PbWriteInt32 ENDP

;; =============================================================================
;; PbWriteSubmsg — Write a submessage field: tag + varint(len) + raw submsg bytes
;; Same as PbWriteBytes but semantically for nested messages.
;; =============================================================================
PbWriteSubmsg PROC uses esi edi pBuf:DWORD, dwFieldNum:DWORD, lpSubmsg:DWORD, cbSubmsg:DWORD
    invoke  PbWriteBytes, pBuf, dwFieldNum, lpSubmsg, cbSubmsg
    ret
PbWriteSubmsg ENDP

;; =============================================================================
;; PbSkipField — Skip a field at *ppBuf based on wire type
;; Args: ppBuf (ptr to read ptr), wireType
;; =============================================================================
PbSkipField PROC ppBuf:DWORD, dwWireType:DWORD
    LOCAL   dummy:DWORD

    cmp     dwWireType, PB_VARINT
    je      @psf_varint
    cmp     dwWireType, PB_LEN
    je      @psf_len
    ;; Unknown wire type — can't skip safely
    mov     eax, -1
    ret

@psf_varint:
    invoke  PbDecodeVarint, ppBuf, ADDR dummy
    ret

@psf_len:
    invoke  PbDecodeVarint, ppBuf, ADDR dummy
    ;; Skip dummy bytes
    mov     edx, ppBuf
    mov     eax, [edx]
    add     eax, dummy
    mov     [edx], eax
    xor     eax, eax
    ret
PbSkipField ENDP
