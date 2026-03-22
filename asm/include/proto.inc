;; =============================================================================
;; proto.inc — mrsh wire protocol (binary framing + command dispatch)
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; Wire format: 4-byte LE length + payload
;; Payload: 1-byte command ID + variable data
;; Auth: challenge-response with ECDSA signature
;; Requires: tls.inc, crypto.inc
;; =============================================================================

;; ---- Command IDs ----
;; Auth IDs aligned with Rust binproto.rs msg::
CMD_AUTH_REQUEST    equ 01h     ; client → server: pubkey + version + caps
CMD_AUTH_CHALLENGE  equ 02h     ; server → client: 32-byte nonce
CMD_AUTH_RESPONSE   equ 03h     ; client → server: 64-byte signature
CMD_AUTH_OK         equ 04h     ; server → client: version + caps
CMD_AUTH_FAIL       equ 05h     ; server → client: error string
CMD_EXEC            equ 10h     ; client → server: command string
CMD_EXEC_RESULT     equ 11h     ; server → client: output string
CMD_EXEC_EXIT       equ 12h     ; server → client: exit code
CMD_PUSH_START      equ 20h     ; client → server: filename + size
CMD_PUSH_DATA       equ 21h     ; client → server: file chunk
CMD_PUSH_END        equ 22h     ; client → server: transfer done
CMD_PUSH_OK         equ 23h     ; server → client: push complete
CMD_PULL_REQ        equ 30h     ; client → server: filename
CMD_PULL_DATA       equ 31h     ; server → client: file chunk
CMD_PULL_END        equ 32h     ; server → client: transfer done
CMD_INFO_REQ        equ 40h     ; client → server: request info
CMD_INFO_RESP       equ 41h     ; server → client: JSON info
CMD_PING            equ 50h     ; client → server: ping
CMD_PONG            equ 51h     ; server → client: pong
CMD_SCREENSHOT_REQ  equ 60h     ; client → server: capture screen
CMD_SCREENSHOT_DATA equ 61h     ; server → client: JPEG data
CMD_SELF_UPDATE     equ 70h     ; client → server: new binary path
CMD_SELF_UPDATE_OK  equ 71h     ; server → client: update scheduled
CMD_SHELL_REQ       equ 80h     ; client → server: shell session request
CMD_SHELL_DATA      equ 81h     ; bidirectional: shell I/O data
CMD_SHELL_RESIZE    equ 82h     ; client → server: terminal resize
CMD_SYNC_REQ        equ 90h     ; client → server: delta pull (send sigs, get M/D/E)
CMD_SYNC_RESP       equ 91h     ; server → client: sync response (M/D/E markers)
CMD_SYNC_PUSH       equ 92h     ; client → server: delta push (request remote sigs)
CMD_SYNC_SIGS       equ 93h     ; server → client: file signatures
CMD_SYNC_DELTA      equ 94h     ; client → server: M/D/E delta data
CMD_SYNC_DONE       equ 95h     ; server → client: push complete
CMD_WRITE           equ 0A0h    ; client → server: write file (path + content)
CMD_WRITE_OK        equ 0A1h    ; server → client: write complete
CMD_NATIVE          equ 0B0h    ; client → server: native command (sub-cmd byte)
CMD_NATIVE_RESP     equ 0B1h    ; server → client: native response
CMD_INPUT           equ 0C0h    ; client → server: GUI input (sub-cmd byte)
CMD_INPUT_RESP      equ 0C1h    ; server → client: GUI input response
CMD_PROXY_CONNECT   equ 0D0h    ; client → proxy: connect to target
CMD_PROXY_OK        equ 0D1h    ; proxy → client: tunnel established
CMD_REQUEST         equ 0F0h    ; generic request (JSON fallback)
CMD_RESPONSE        equ 0F1h    ; generic response (JSON fallback)
CMD_ERROR           equ 0FFh    ; either direction: error message

;; Compression flags (prepended to compressed payloads)
COMPRESS_RAW        equ 00h     ; no compression
COMPRESS_ZSTD       equ 01h     ; zstd compressed

;; ---- Message structure (in-memory, not on wire) ----
MRSH_MSG STRUCT
    cmdId    BYTE  ?
    _pad     BYTE  3 dup(?)     ; alignment
    dataLen  DWORD ?
    pData    DWORD ?             ; ptr to payload (after cmdId on wire)
MRSH_MSG ENDS

;; ---- Kernel32 protos ----
IFNDEF _RTLZEROMEMORY_DEFINED
_RTLZEROMEMORY_DEFINED equ 1
RtlZeroMemory   PROTO :DWORD, :DWORD
ENDIF
IFNDEF _RTLCOPYMEMORY_DEFINED
_RTLCOPYMEMORY_DEFINED equ 1
RtlMoveMemory   PROTO :DWORD, :DWORD, :DWORD
ENDIF
IFNDEF _GLOBALALLOC_DEFINED
_GLOBALALLOC_DEFINED equ 1
GlobalAlloc     PROTO :DWORD, :DWORD
GlobalFree      PROTO :DWORD
ENDIF

;; ---- String functions ----
lstrlenA    PROTO :DWORD

.code

;; =============================================================================
;; ProtoSendMsg — Send a protocol message over TLS
;; Wire format: [4-byte total len][1-byte cmdId][payload]
;; Args: pTlsCtx, cmdId (BYTE), lpPayload, nPayloadLen
;; Returns: 0 = success, -1 = error
;; =============================================================================
ProtoSendMsg PROC pTlsCtx:DWORD, bCmdId:BYTE, lpPayload:DWORD, nPayloadLen:DWORD
    LOCAL   pBuf:DWORD
    LOCAL   totalLen:DWORD

    ;; Total = 1 (cmdId) + payloadLen
    mov     eax, nPayloadLen
    inc     eax
    mov     totalLen, eax

    ;; Allocate buffer: cmdId + payload
    invoke  GlobalAlloc, 0, totalLen
    test    eax, eax
    jz      @psm_fail
    mov     pBuf, eax

    ;; Write cmdId
    mov     edx, pBuf
    mov     al, bCmdId
    mov     byte ptr [edx], al

    ;; Copy payload after cmdId
    cmp     nPayloadLen, 0
    je      @psm_send
    mov     edx, pBuf
    inc     edx
    invoke  RtlMoveMemory, edx, lpPayload, nPayloadLen

@psm_send:
    ;; Send as length-prefixed TLS message
    invoke  TlsSendLenPrefixed, pTlsCtx, pBuf, totalLen
    push    eax
    invoke  GlobalFree, pBuf
    pop     eax
    ret

@psm_fail:
    mov     eax, -1
    ret
ProtoSendMsg ENDP

;; =============================================================================
;; ProtoRecvMsg — Receive a protocol message from TLS
;; Args: pTlsCtx, pMsg (ptr to MRSH_MSG, receives parsed message)
;; Returns: 0 = success, -1 = error
;; Caller must GlobalFree pMsg->pData when done
;; =============================================================================
ProtoRecvMsg PROC uses ebx esi edi pTlsCtx:DWORD, pMsg:DWORD
    LOCAL   pBuf:DWORD
    LOCAL   bufLen:DWORD

    ;; Receive length-prefixed message
    invoke  TlsRecvLenPrefixed, pTlsCtx, ADDR pBuf, ADDR bufLen
    test    eax, eax
    jnz     @prm_fail

    ;; Must have at least 1 byte (cmdId)
    cmp     bufLen, 0
    je      @prm_free

    ;; Parse: first byte = cmdId, rest = payload
    mov     edx, pMsg
    mov     esi, pBuf
    mov     al, byte ptr [esi]
    mov     (MRSH_MSG PTR [edx]).cmdId, al

    mov     eax, bufLen
    dec     eax                     ; payload length = total - 1
    mov     (MRSH_MSG PTR [edx]).dataLen, eax

    ;; If payload exists, allocate separate buffer +1 for null terminator
    cmp     eax, 0
    je      @prm_no_data

    push    eax                     ; save payload len
    inc     eax                     ; +1 for null terminator
    invoke  GlobalAlloc, 0, eax
    pop     ecx                     ; restore payload len
    test    eax, eax
    jz      @prm_free
    mov     edx, pMsg
    mov     (MRSH_MSG PTR [edx]).pData, eax

    ;; Copy payload (skip cmdId byte) + null terminate
    mov     esi, pBuf
    inc     esi
    mov     edi, eax                ; edi = pData (preserved across invoke)
    mov     ebx, ecx                ; ebx = payload len (preserved)
    invoke  RtlMoveMemory, edi, esi, ebx
    mov     byte ptr [edi + ebx], 0 ; null terminate
    jmp     @prm_ok

@prm_no_data:
    mov     edx, pMsg
    mov     (MRSH_MSG PTR [edx]).pData, NULL

@prm_ok:
    invoke  GlobalFree, pBuf
    xor     eax, eax
    ret

@prm_free:
    invoke  GlobalFree, pBuf
@prm_fail:
    mov     eax, -1
    ret
ProtoRecvMsg ENDP

;; =============================================================================
;; EncodeStr — Write 2-byte BE length + string to buffer (binproto compat)
;; Args: lpBuf (write position), lpStr (ASCIIZ), nStrLen
;; Returns: bytes written (2 + nStrLen)
;; =============================================================================
EncodeStr PROC lpBuf:DWORD, lpStr:DWORD, nStrLen:DWORD
    mov     edx, lpBuf
    ;; Write 2-byte BE length
    mov     eax, nStrLen
    mov     byte ptr [edx], ah      ; high byte
    mov     byte ptr [edx + 1], al  ; low byte
    add     edx, 2
    ;; Copy string bytes
    cmp     nStrLen, 0
    je      @es_done
    invoke  RtlMoveMemory, edx, lpStr, nStrLen
@es_done:
    mov     eax, nStrLen
    add     eax, 2
    ret
EncodeStr ENDP

;; =============================================================================
;; EncodeBlob — Write 4-byte BE length + raw data to buffer (binproto compat)
;; Args: lpBuf (write position), lpData, nDataLen
;; Returns: bytes written (4 + nDataLen)
;; =============================================================================
EncodeBlob PROC lpBuf:DWORD, lpData:DWORD, nDataLen:DWORD
    mov     edx, lpBuf
    ;; Write 4-byte BE length
    mov     eax, nDataLen
    bswap   eax
    mov     [edx], eax
    add     edx, 4
    ;; Copy data
    cmp     nDataLen, 0
    je      @eb_done
    invoke  RtlMoveMemory, edx, lpData, nDataLen
@eb_done:
    mov     eax, nDataLen
    add     eax, 4
    ret
EncodeBlob ENDP

;; =============================================================================
;; DecodeStr — Read 2-byte BE length + string from buffer
;; Args: lpBuf (read position)
;; Returns: eax = string length, edx = ptr to string data (inside lpBuf)
;; =============================================================================
DecodeStr PROC lpBuf:DWORD
    mov     edx, lpBuf
    movzx   eax, byte ptr [edx]     ; high byte
    shl     eax, 8
    movzx   ecx, byte ptr [edx + 1] ; low byte
    or      eax, ecx                 ; eax = string length
    lea     edx, [edx + 2]          ; edx = ptr to string data
    ret
DecodeStr ENDP

;; =============================================================================
;; ProtoSendExec — Send exec command (binproto format)
;; Payload: encode_str(command) + env_count(0)
;; =============================================================================
ProtoSendExec PROC uses esi edi pTlsCtx:DWORD, lpCommand:DWORD
    LOCAL   nLen:DWORD
    LOCAL   pBuf:DWORD
    LOCAL   cbBuf:DWORD

    invoke  lstrlenA, lpCommand
    mov     nLen, eax
    ;; Total payload: 2 (str len) + nLen + 1 (env_count=0)
    mov     eax, nLen
    add     eax, 3
    mov     cbBuf, eax
    invoke  GlobalAlloc, 0, cbBuf
    test    eax, eax
    jz      @pse_fail
    mov     pBuf, eax

    invoke  EncodeStr, pBuf, lpCommand, nLen
    ;; Write env_count = 0
    mov     edx, pBuf
    add     edx, 2
    add     edx, nLen
    mov     byte ptr [edx], 0

    invoke  ProtoSendMsg, pTlsCtx, CMD_EXEC, pBuf, cbBuf
    push    eax
    invoke  GlobalFree, pBuf
    pop     eax
    ret
@pse_fail:
    mov     eax, -1
    ret
ProtoSendExec ENDP

;; =============================================================================
;; ProtoSendResult — Send exec result (binproto format)
;; Payload: exit_code(4 LE) + encode_blob(output)
;; =============================================================================
ProtoSendResult PROC uses esi edi pTlsCtx:DWORD, lpOutput:DWORD, nExitCode:DWORD
    LOCAL   nLen:DWORD
    LOCAL   pBuf:DWORD
    LOCAL   cbBuf:DWORD

    invoke  lstrlenA, lpOutput
    mov     nLen, eax
    ;; Total: 4 (exit_code) + 4 (blob len) + nLen
    mov     eax, nLen
    add     eax, 8
    mov     cbBuf, eax
    invoke  GlobalAlloc, 0, cbBuf
    test    eax, eax
    jz      @psr_fail
    mov     pBuf, eax

    ;; Write exit code (4 bytes LE)
    mov     edx, pBuf
    mov     eax, nExitCode
    mov     [edx], eax

    ;; Write output blob (4-byte BE length + raw)
    mov     edx, pBuf
    add     edx, 4
    invoke  EncodeBlob, edx, lpOutput, nLen

    invoke  ProtoSendMsg, pTlsCtx, CMD_EXEC_RESULT, pBuf, cbBuf
    push    eax
    invoke  GlobalFree, pBuf
    pop     eax
    ret
@psr_fail:
    mov     eax, -1
    ret
ProtoSendResult ENDP

;; =============================================================================
;; ProtoSendError — Send error message (binproto format)
;; Payload: encode_str(error)
;; =============================================================================
ProtoSendError PROC uses esi edi pTlsCtx:DWORD, lpError:DWORD
    LOCAL   nLen:DWORD
    LOCAL   pBuf:DWORD
    LOCAL   cbBuf:DWORD

    invoke  lstrlenA, lpError
    mov     nLen, eax
    mov     eax, nLen
    add     eax, 2
    mov     cbBuf, eax
    invoke  GlobalAlloc, 0, cbBuf
    test    eax, eax
    jz      @perr_fail
    mov     pBuf, eax

    invoke  EncodeStr, pBuf, lpError, nLen

    invoke  ProtoSendMsg, pTlsCtx, CMD_ERROR, pBuf, cbBuf
    push    eax
    invoke  GlobalFree, pBuf
    pop     eax
    ret
@perr_fail:
    mov     eax, -1
    ret
ProtoSendError ENDP

;; =============================================================================
;; ProtoSendPing / ProtoSendPong — Heartbeat
;; =============================================================================
ProtoSendPing PROC pTlsCtx:DWORD
    invoke  ProtoSendMsg, pTlsCtx, CMD_PING, NULL, 0
    ret
ProtoSendPing ENDP

ProtoSendPong PROC pTlsCtx:DWORD
    invoke  ProtoSendMsg, pTlsCtx, CMD_PONG, NULL, 0
    ret
ProtoSendPong ENDP

;; =============================================================================
;; ProtoFreeMsg — Free message payload
;; =============================================================================
ProtoFreeMsg PROC pMsg:DWORD
    mov     edx, pMsg
    mov     eax, (MRSH_MSG PTR [edx]).pData
    test    eax, eax
    jz      @pfm_done
    invoke  GlobalFree, eax
    mov     edx, pMsg
    mov     (MRSH_MSG PTR [edx]).pData, NULL
@pfm_done:
    ret
ProtoFreeMsg ENDP

