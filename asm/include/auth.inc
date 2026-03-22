;; =============================================================================
;; auth.inc — Ed25519 auth (binary protocol, Rust interop)
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; Uses TweetNaCl Ed25519 via ed25519_wrap.obj
;; Key files: C:\ProgramData\mrsh\id_ed25519 (64B), id_ed25519.pub (32B)
;; Binary auth: server auto-detects 0x01=binary vs 0x7B=JSON
;; =============================================================================

CreateDirectoryA PROTO :DWORD, :DWORD
GetFileSize     PROTO :DWORD, :DWORD

Ed25519Sign     PROTO :DWORD, :DWORD, :DWORD, :DWORD
Ed25519Verify   PROTO :DWORD, :DWORD, :DWORD, :DWORD
Ed25519Keypair  PROTO :DWORD, :DWORD

NONCE_SIZE      equ 32
ED25519_SIGSIZE equ 64
ED25519_PKSIZE  equ 32
ED25519_SKSIZE  equ 64

.data
    _szDataDir      db "C:\ProgramData\mrsh", 0
    _szAuthKeysFile db "C:\ProgramData\mrsh\authorized_keys", 0
    _szKeyPriv      db "C:\ProgramData\mrsh\id_ed25519", 0
    _szKeyPub       db "C:\ProgramData\mrsh\id_ed25519.pub", 0
    _szAuthFail     db "authentication failed", 0
    _szAuthVer      db "pmash 0.1.0", 0
    _szADbg1        db "[auth] key loaded ok", 13, 10, 0
    _szADbg2        db "[auth] sent AUTH_REQUEST", 13, 10, 0
    _szADbg3        db "[auth] recv failed or wrong cmdId=%02X", 13, 10, 0
    _szADbg4        db "[auth] recv AUTH_OK failed cmdId=%02X", 13, 10, 0
    _szADbg5        db "[auth] ProtoRecvMsg returned error", 13, 10, 0

.data?
    _authDbgBuf     BYTE 128 dup(?)

.data?
    _authNonce      BYTE 32 dup(?)
    _authSig        BYTE 64 dup(?)
    _authPubKey     BYTE 32 dup(?)
    _authPrivKey    BYTE 64 dup(?)
    _authBuf        BYTE 256 dup(?)

LogMsg PROTO :DWORD
StdErr PROTO :DWORD

.code

;; Load Ed25519 keypair from files, or generate new
_AuthLoadOrGenKey PROC
    LOCAL   hFile:DWORD
    LOCAL   dwRead:DWORD
    invoke  CreateDirectoryA, ADDR _szDataDir, 0
    ;; Load private key
    invoke  CreateFileA, ADDR _szKeyPriv, GENERIC_READ, 0, \
            0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0
    cmp     eax, INVALID_HANDLE_VALUE
    je      @alk_gen
    mov     hFile, eax
    invoke  ReadFile, hFile, ADDR _authPrivKey, ED25519_SKSIZE, ADDR dwRead, 0
    invoke  CloseHandle, hFile
    cmp     dwRead, ED25519_SKSIZE
    jne     @alk_gen
    ;; Load public key
    invoke  CreateFileA, ADDR _szKeyPub, GENERIC_READ, 0, \
            0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0
    cmp     eax, INVALID_HANDLE_VALUE
    je      @alk_gen
    mov     hFile, eax
    invoke  ReadFile, hFile, ADDR _authPubKey, ED25519_PKSIZE, ADDR dwRead, 0
    invoke  CloseHandle, hFile
    cmp     dwRead, ED25519_PKSIZE
    jne     @alk_gen
    xor     eax, eax
    ret
@alk_gen:
    invoke  Ed25519Keypair, ADDR _authPubKey, ADDR _authPrivKey
    invoke  CreateFileA, ADDR _szKeyPriv, GENERIC_WRITE, 0, \
            0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0
    cmp     eax, INVALID_HANDLE_VALUE
    je      @alk_fail
    mov     hFile, eax
    invoke  WriteFile, hFile, ADDR _authPrivKey, ED25519_SKSIZE, ADDR dwRead, 0
    invoke  CloseHandle, hFile
    invoke  CreateFileA, ADDR _szKeyPub, GENERIC_WRITE, 0, \
            0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0
    cmp     eax, INVALID_HANDLE_VALUE
    je      @alk_fail
    mov     hFile, eax
    invoke  WriteFile, hFile, ADDR _authPubKey, ED25519_PKSIZE, ADDR dwRead, 0
    invoke  CloseHandle, hFile
    xor     eax, eax
    ret
@alk_fail:
    mov     eax, -1
    ret
_AuthLoadOrGenKey ENDP

;; =============================================================================
;; AuthServerHandshake — Server-side binary auth
;; =============================================================================
AuthServerHandshake PROC uses ebx esi edi pTlsCtx:DWORD
    LOCAL   msg:MRSH_MSG
    LOCAL   cbPubBlob:DWORD
    ;; Receive AUTH_REQUEST
    invoke  ProtoRecvMsg, pTlsCtx, ADDR msg
    test    eax, eax
    jnz     @ash_fail
    cmp     msg.cmdId, CMD_AUTH_REQUEST
    jne     @ash_reject
    ;; Parse: decode_blob(pubkey) at offset 0
    cmp     msg.dataLen, 4
    jb      @ash_reject
    mov     edx, msg.pData
    mov     eax, [edx]
    bswap   eax
    mov     cbPubBlob, eax
    cmp     eax, ED25519_PKSIZE
    jne     @ash_reject
    add     edx, 4
    invoke  RtlMoveMemory, ADDR _authPubKey, edx, ED25519_PKSIZE
    invoke  ProtoFreeMsg, ADDR msg
    ;; Send challenge
    invoke  CryptoRandom, ADDR _authNonce, NONCE_SIZE
    test    eax, eax
    jnz     @ash_fail
    invoke  ProtoSendMsg, pTlsCtx, CMD_AUTH_CHALLENGE, ADDR _authNonce, NONCE_SIZE
    test    eax, eax
    jnz     @ash_fail
    ;; Receive signature
    invoke  ProtoRecvMsg, pTlsCtx, ADDR msg
    test    eax, eax
    jnz     @ash_fail
    cmp     msg.cmdId, CMD_AUTH_RESPONSE
    jne     @ash_reject
    cmp     msg.dataLen, ED25519_SIGSIZE
    jne     @ash_reject
    ;; Verify
    invoke  Ed25519Verify, msg.pData, ADDR _authNonce, NONCE_SIZE, ADDR _authPubKey
    test    eax, eax
    jnz     @ash_reject
    ;; Accept
    invoke  ProtoFreeMsg, ADDR msg
    ;; AUTH_OK: encode_str(version) + caps(0) + no_banner(0)
    lea     edi, _authBuf
    mov     byte ptr [edi], 0
    mov     byte ptr [edi + 1], 11
    add     edi, 2
    invoke  RtlMoveMemory, edi, ADDR _szAuthVer, 11
    lea     edi, _authBuf
    mov     byte ptr [edi + 13], 0
    mov     byte ptr [edi + 14], 0
    invoke  ProtoSendMsg, pTlsCtx, CMD_AUTH_OK, ADDR _authBuf, 15
    xor     eax, eax
    ret
@ash_reject:
    invoke  ProtoFreeMsg, ADDR msg
    invoke  lstrlenA, ADDR _szAuthFail
    mov     ecx, eax
    lea     edi, _authBuf
    invoke  EncodeStr, edi, ADDR _szAuthFail, ecx
    add     ecx, 2
    invoke  ProtoSendMsg, pTlsCtx, CMD_AUTH_FAIL, ADDR _authBuf, ecx
@ash_fail:
    mov     eax, -1
    ret
AuthServerHandshake ENDP

;; =============================================================================
;; AuthClientHandshake — Client-side binary auth (Rust server compatible)
;; Binary protocol: server detects 0x01 = AUTH_REQUEST
;; =============================================================================
AuthClientHandshake PROC uses ebx esi edi pTlsCtx:DWORD
    LOCAL   msg:MRSH_MSG

    invoke  _AuthLoadOrGenKey
    test    eax, eax
    jnz     @ach_fail
    cmp     cliArgs.bVerbose, 0
    je      @ach_skip_dbg1
    invoke  StdErr, ADDR _szADbg1
@ach_skip_dbg1:

    ;; Build AUTH_REQUEST: encode_blob(32B pubkey) + encode_str(version) + caps(0)
    lea     edi, _authBuf
    ;; encode_blob: 4-byte BE len + 32 bytes pubkey
    mov     eax, ED25519_PKSIZE
    bswap   eax
    mov     [edi], eax
    add     edi, 4
    invoke  RtlMoveMemory, edi, ADDR _authPubKey, ED25519_PKSIZE
    ;; encode_str: 2-byte BE len + "pmash 0.1.0" (11 chars)
    lea     edi, _authBuf
    add     edi, 36
    mov     byte ptr [edi], 0
    mov     byte ptr [edi + 1], 11
    add     edi, 2
    invoke  RtlMoveMemory, edi, ADDR _szAuthVer, 11
    ;; caps_count = 0
    lea     edi, _authBuf
    mov     byte ptr [edi + 49], 0
    ;; Send: total = 4 + 32 + 2 + 11 + 1 = 50 bytes
    invoke  ProtoSendMsg, pTlsCtx, CMD_AUTH_REQUEST, ADDR _authBuf, 50
    test    eax, eax
    jnz     @ach_fail
    cmp     cliArgs.bVerbose, 0
    je      @ach_skip_dbg2
    invoke  StdErr, ADDR _szADbg2
@ach_skip_dbg2:

    ;; Receive challenge (32B nonce)
    invoke  ProtoRecvMsg, pTlsCtx, ADDR msg
    test    eax, eax
    jnz     @ach_recv1_fail
    cmp     msg.cmdId, CMD_AUTH_CHALLENGE
    jne     @ach_reject

    ;; Sign raw challenge (Ed25519 hashes internally, no SHA256 needed)
    invoke  Ed25519Sign, ADDR _authSig, msg.pData, msg.dataLen, ADDR _authPrivKey
    test    eax, eax
    jnz     @ach_reject
    invoke  ProtoFreeMsg, ADDR msg

    ;; Send signature (64 bytes)
    invoke  ProtoSendMsg, pTlsCtx, CMD_AUTH_RESPONSE, ADDR _authSig, ED25519_SIGSIZE
    test    eax, eax
    jnz     @ach_fail

    ;; Receive AUTH_OK
    invoke  ProtoRecvMsg, pTlsCtx, ADDR msg
    test    eax, eax
    jnz     @ach_recv2_fail
    cmp     msg.cmdId, CMD_AUTH_OK
    jne     @ach_auth_fail
    invoke  ProtoFreeMsg, ADDR msg
    xor     eax, eax
    ret

@ach_recv1_fail:
    cmp     cliArgs.bVerbose, 0
    je      @ach_fail
    invoke  StdErr, ADDR _szADbg5
    jmp     @ach_fail
@ach_recv2_fail:
    cmp     cliArgs.bVerbose, 0
    je      @ach_fail
    invoke  StdErr, ADDR _szADbg5
    jmp     @ach_fail
@ach_auth_fail:
    cmp     cliArgs.bVerbose, 0
    je      @ach_auth_fail_quiet
    movzx   eax, msg.cmdId
    invoke  wsprintfA, ADDR _authDbgBuf, ADDR _szADbg4, eax
    invoke  StdErr, ADDR _authDbgBuf
@ach_auth_fail_quiet:
    invoke  ProtoFreeMsg, ADDR msg
    jmp     @ach_fail
@ach_reject:
    cmp     cliArgs.bVerbose, 0
    je      @ach_reject_quiet
    movzx   eax, msg.cmdId
    invoke  wsprintfA, ADDR _authDbgBuf, ADDR _szADbg3, eax
    invoke  StdErr, ADDR _authDbgBuf
@ach_reject_quiet:
    invoke  ProtoFreeMsg, ADDR msg
@ach_fail:
    mov     eax, -1
    ret
AuthClientHandshake ENDP
