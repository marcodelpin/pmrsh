;; =============================================================================
;; transfer.inc — File push/pull over TLS
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; Uses proto.inc CMD_PUSH_START/DATA/END and CMD_PULL_REQ/DATA/END
;; =============================================================================

IFNDEF _GLOBALALLOC_DEFINED
_GLOBALALLOC_DEFINED equ 1
GlobalAlloc     PROTO :DWORD, :DWORD
GlobalFree      PROTO :DWORD
ENDIF
CreateFileA     PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
ReadFile        PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
WriteFile       PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
CloseHandle     PROTO :DWORD
GetFileSize     PROTO :DWORD, :DWORD
lstrlenA        PROTO :DWORD

IFNDEF GENERIC_READ
GENERIC_READ    equ 80000000h
ENDIF
IFNDEF GENERIC_WRITE
GENERIC_WRITE   equ 40000000h
ENDIF
IFNDEF CREATE_ALWAYS
CREATE_ALWAYS   equ 2
ENDIF
IFNDEF OPEN_EXISTING
OPEN_EXISTING   equ 3
ENDIF
IFNDEF INVALID_HANDLE_VALUE
INVALID_HANDLE_VALUE equ 0FFFFFFFFh
ENDIF
IFNDEF FILE_ATTRIBUTE_NORMAL
FILE_ATTRIBUTE_NORMAL equ 80h
ENDIF

PUSH_CHUNK_SIZE equ 32768      ; 32KB chunks

LogMsg PROTO :DWORD
wsprintfA PROTO C :DWORD, :DWORD, :VARARG

.data
    _szFileNotFound db "file not found", 0
    _szPushDbg  db "[push] recv=%d cmd=%02x dLen=%d", 13, 10, 0
    _szPushOpen db "[push] file opened ok", 13, 10, 0

.data?
    _pushDbg    BYTE 128 dup(?)

.code

;; =============================================================================
;; TransferPush — Push local file to remote via TLS
;; Args: pTlsCtx, lpLocalPath, lpRemotePath
;; Returns: 0 = success, -1 = error
;; =============================================================================
TransferPush PROC uses ebx esi edi \
    pTlsCtx:DWORD, lpLocalPath:DWORD, lpRemotePath:DWORD

    LOCAL   hFile:DWORD
    LOCAL   cbFile:DWORD
    LOCAL   pChunk:DWORD
    LOCAL   dwRead:DWORD
    LOCAL   hdr[8]:BYTE     ; remote path length (4) + file size (4)

    ;; Open local file
    invoke  CreateFileA, lpLocalPath, GENERIC_READ, 0, \
            0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0
    cmp     eax, INVALID_HANDLE_VALUE
    je      @tp_fail
    mov     hFile, eax

    invoke  GetFileSize, hFile, 0
    mov     cbFile, eax

    ;; Send CMD_PUSH_START: file_size(8LE) + encode_str(remote_path)
    invoke  lstrlenA, lpRemotePath
    push    eax                     ; save path len
    ;; Build PUSH_START payload in hdr buffer (use stack local)
    ;; 8 bytes file_size + 2 bytes path_len + path
    mov     eax, cbFile
    mov     dword ptr [hdr], eax    ; file_size low 32 bits (LE)
    mov     dword ptr [hdr + 4], 0  ; file_size high 32 bits = 0
    pop     ecx                     ; path len
    push    ecx
    ;; Need larger buffer — use GlobalAlloc
    add     ecx, 10                 ; 8 + 2 + path_len
    invoke  GlobalAlloc, 0, ecx
    test    eax, eax
    jz      @tp_close
    mov     pChunk, eax             ; temporary reuse
    ;; Copy file_size (8 bytes LE)
    invoke  RtlMoveMemory, pChunk, ADDR hdr, 8
    ;; encode_str(path)
    mov     edi, pChunk
    add     edi, 8
    pop     ecx                     ; path len
    push    ecx
    invoke  EncodeStr, edi, lpRemotePath, ecx
    pop     ecx
    add     ecx, 10                 ; total payload size
    invoke  ProtoSendMsg, pTlsCtx, CMD_PUSH_START, pChunk, ecx
    invoke  GlobalFree, pChunk

    ;; Allocate chunk buffer
    invoke  GlobalAlloc, 0, PUSH_CHUNK_SIZE
    test    eax, eax
    jz      @tp_close
    mov     pChunk, eax

    ;; Send file in chunks
@tp_loop:
    invoke  ReadFile, hFile, pChunk, PUSH_CHUNK_SIZE, ADDR dwRead, 0
    test    eax, eax
    jz      @tp_end
    cmp     dwRead, 0
    je      @tp_end

    invoke  ProtoSendMsg, pTlsCtx, CMD_PUSH_DATA, pChunk, dwRead
    test    eax, eax
    jnz     @tp_free
    jmp     @tp_loop

@tp_end:
    ;; Send CMD_PUSH_END
    invoke  ProtoSendMsg, pTlsCtx, CMD_PUSH_END, 0, 0

    invoke  GlobalFree, pChunk
    invoke  CloseHandle, hFile
    xor     eax, eax
    ret

@tp_free:
    invoke  GlobalFree, pChunk
@tp_close:
    invoke  CloseHandle, hFile
@tp_fail:
    mov     eax, -1
    ret
TransferPush ENDP

;; =============================================================================
;; TransferPull — Pull remote file to local via TLS
;; Args: pTlsCtx, lpRemotePath, lpLocalPath
;; Returns: 0 = success, -1 = error
;; =============================================================================
TransferPull PROC uses ebx esi edi \
    pTlsCtx:DWORD, lpRemotePath:DWORD, lpLocalPath:DWORD

    LOCAL   hFile:DWORD
    LOCAL   msg:MRSH_MSG
    LOCAL   dwWritten:DWORD

    ;; Send pull request: encode_str(remote_path)
    invoke  lstrlenA, lpRemotePath
    push    eax
    add     eax, 2
    invoke  GlobalAlloc, 0, eax
    pop     ecx
    test    eax, eax
    jz      @tpl_fail
    push    eax                 ; save pBuf
    push    ecx                 ; save pathLen
    invoke  EncodeStr, eax, lpRemotePath, ecx
    pop     ecx
    add     ecx, 2              ; total payload
    pop     eax                 ; pBuf
    push    eax
    invoke  ProtoSendMsg, pTlsCtx, CMD_PULL_REQ, eax, ecx
    pop     eax
    invoke  GlobalFree, eax

    ;; Open local file for writing
    invoke  CreateFileA, lpLocalPath, GENERIC_WRITE, 0, \
            0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0
    cmp     eax, INVALID_HANDLE_VALUE
    je      @tpl_fail
    mov     hFile, eax

    ;; Receive data chunks until CMD_PULL_END
@tpl_loop:
    invoke  ProtoRecvMsg, pTlsCtx, ADDR msg
    test    eax, eax
    jnz     @tpl_close

    cmp     msg.cmdId, CMD_PULL_DATA
    jne     @tpl_check_end

    ;; Write chunk to file
    invoke  WriteFile, hFile, msg.pData, msg.dataLen, ADDR dwWritten, 0
    invoke  ProtoFreeMsg, ADDR msg
    jmp     @tpl_loop

@tpl_check_end:
    invoke  ProtoFreeMsg, ADDR msg
    cmp     msg.cmdId, CMD_PULL_END
    je      @tpl_done
    cmp     msg.cmdId, CMD_ERROR
    je      @tpl_close
    jmp     @tpl_loop

@tpl_done:
    invoke  CloseHandle, hFile
    xor     eax, eax
    ret

@tpl_close:
    invoke  CloseHandle, hFile
@tpl_fail:
    mov     eax, -1
    ret
TransferPull ENDP

;; =============================================================================
;; TransferHandlePush — Server-side: receive pushed file
;; Args: pTlsCtx, pFirstMsg (the CMD_PUSH_START message)
;; Returns: 0 = success
;; =============================================================================
;; =============================================================================
;; TransferHandlePull — Server-side: send requested file to client
;; Args: pTlsCtx, pFirstMsg (the CMD_PULL_REQ message, payload = remote path)
;; Returns: 0 = success
;; =============================================================================
TransferHandlePull PROC uses ebx esi edi \
    pTlsCtx:DWORD, pFirstMsg:DWORD

    LOCAL   hFile:DWORD
    LOCAL   pChunk:DWORD
    LOCAL   dwRead:DWORD
    LOCAL   szErr[64]:BYTE

    ;; First message payload: decode_str(remote_path)
    mov     edx, pFirstMsg
    mov     esi, (MRSH_MSG PTR [edx]).pData
    ;; Read 2-byte BE string length
    movzx   eax, byte ptr [esi]
    shl     eax, 8
    movzx   ecx, byte ptr [esi + 1]
    or      eax, ecx
    add     esi, 2              ; esi = path string, eax = length
    mov     byte ptr [esi + eax], 0  ; null-terminate

    ;; Open file for reading
    invoke  CreateFileA, esi, GENERIC_READ, 0, \
            0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0
    cmp     eax, INVALID_HANDLE_VALUE
    je      @thpl_notfound
    mov     hFile, eax

    ;; Allocate chunk buffer
    invoke  GlobalAlloc, 0, PUSH_CHUNK_SIZE
    test    eax, eax
    jz      @thpl_closefile
    mov     pChunk, eax

    ;; Send file in chunks
@thpl_loop:
    invoke  ReadFile, hFile, pChunk, PUSH_CHUNK_SIZE, ADDR dwRead, 0
    test    eax, eax
    jz      @thpl_end
    cmp     dwRead, 0
    je      @thpl_end

    invoke  ProtoSendMsg, pTlsCtx, CMD_PULL_DATA, pChunk, dwRead
    test    eax, eax
    jnz     @thpl_free
    jmp     @thpl_loop

@thpl_end:
    ;; Send CMD_PULL_END
    invoke  ProtoSendMsg, pTlsCtx, CMD_PULL_END, 0, 0

    invoke  GlobalFree, pChunk
    invoke  CloseHandle, hFile
    xor     eax, eax
    ret

@thpl_free:
    invoke  GlobalFree, pChunk
@thpl_closefile:
    invoke  CloseHandle, hFile
    mov     eax, -1
    ret

@thpl_notfound:
    invoke  ProtoSendError, pTlsCtx, ADDR _szFileNotFound
    mov     eax, -1
    ret
TransferHandlePull ENDP

;; NOTE: Push is handled inline in server.inc (@sl_push) for reliability.
;; This proc is kept for reference but is NOT called from the server loop.
TransferHandlePush PROC uses ebx esi edi \
    pTlsCtx:DWORD, pFirstMsg:DWORD

    LOCAL   hFile:DWORD
    LOCAL   msg:MRSH_MSG
    LOCAL   dwWritten:DWORD

    ;; First message: PUSH_START — binproto: file_size(8LE) + encode_str(path)
    mov     edx, pFirstMsg
    mov     esi, (MRSH_MSG PTR [edx]).pData
    ;; Skip 8-byte file_size (LE), decode path string at offset 8
    add     esi, 8
    ;; Read 2-byte BE string length
    movzx   eax, byte ptr [esi]
    shl     eax, 8
    movzx   ecx, byte ptr [esi + 1]
    or      eax, ecx
    add     esi, 2              ; esi = path string ptr, eax = path length
    ;; Null-terminate the path for CreateFileA
    mov     byte ptr [esi + eax], 0
    ;; Open file for writing
    invoke  CreateFileA, esi, GENERIC_WRITE, 0, \
            0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0
    cmp     eax, INVALID_HANDLE_VALUE
    je      @thp_fail
    mov     hFile, eax
    invoke  LogMsg, ADDR _szPushOpen

@thp_loop:
    invoke  ProtoRecvMsg, pTlsCtx, ADDR msg
    mov     ebx, eax            ; save recv result
    movzx   ecx, msg.cmdId
    invoke  wsprintfA, ADDR _pushDbg, ADDR _szPushDbg, ebx, ecx, msg.dataLen
    invoke  LogMsg, ADDR _pushDbg
    test    ebx, ebx
    jnz     @thp_close

    cmp     msg.cmdId, CMD_PUSH_DATA
    jne     @thp_check_end

    invoke  WriteFile, hFile, msg.pData, msg.dataLen, ADDR dwWritten, 0
    invoke  ProtoFreeMsg, ADDR msg
    jmp     @thp_loop

@thp_check_end:
    invoke  ProtoFreeMsg, ADDR msg
    cmp     msg.cmdId, CMD_PUSH_END
    je      @thp_done
    jmp     @thp_loop

@thp_done:
    invoke  CloseHandle, hFile
    xor     eax, eax
    ret

@thp_close:
    invoke  CloseHandle, hFile
@thp_fail:
    mov     eax, -1
    ret
TransferHandlePush ENDP
