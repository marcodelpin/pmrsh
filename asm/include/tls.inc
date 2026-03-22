;; =============================================================================
;; tls.inc — SChannel TLS wrapper for MASM x86
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; Provides: TlsInit, TlsConnect (client), TlsAccept (server),
;;           TlsSend, TlsRecv, TlsClose
;; Requires: secur32.lib (or sspicli.lib), crypt32.lib, net.inc
;; =============================================================================

;; ---- SSPI Constants ----
SECPKG_CRED_OUTBOUND     equ 00000002h
SECPKG_CRED_INBOUND      equ 00000001h
SEC_E_OK                 equ 00000000h
SEC_I_CONTINUE_NEEDED    equ 00090312h
SEC_E_INCOMPLETE_MESSAGE equ 80090318h
SEC_I_CONTEXT_EXPIRED    equ 00090317h
SEC_I_RENEGOTIATE        equ 00090321h

;; ISC_REQ flags (client)
ISC_REQ_SEQUENCE_DETECT     equ 00000008h
ISC_REQ_REPLAY_DETECT       equ 00000004h
ISC_REQ_CONFIDENTIALITY     equ 00000010h
ISC_REQ_ALLOCATE_MEMORY     equ 00000100h
ISC_REQ_STREAM              equ 00008000h
ISC_REQ_USE_SUPPLIED_CREDS  equ 00000080h
ISC_REQ_MANUAL_CRED_VALIDATION equ 00080000h

ISC_REQ_FLAGS equ ISC_REQ_SEQUENCE_DETECT or ISC_REQ_REPLAY_DETECT or \
                  ISC_REQ_CONFIDENTIALITY or ISC_REQ_ALLOCATE_MEMORY or \
                  ISC_REQ_STREAM or ISC_REQ_MANUAL_CRED_VALIDATION

;; ASC_REQ flags (server)
ASC_REQ_SEQUENCE_DETECT     equ 00000008h
ASC_REQ_REPLAY_DETECT       equ 00000004h
ASC_REQ_CONFIDENTIALITY     equ 00000010h
ASC_REQ_ALLOCATE_MEMORY     equ 00000100h
ASC_REQ_STREAM              equ 00008000h

ASC_REQ_FLAGS equ ASC_REQ_SEQUENCE_DETECT or ASC_REQ_REPLAY_DETECT or \
                  ASC_REQ_CONFIDENTIALITY or ASC_REQ_ALLOCATE_MEMORY or \
                  ASC_REQ_STREAM

;; Buffer types
SECBUFFER_TOKEN         equ 2
SECBUFFER_EMPTY         equ 0
SECBUFFER_DATA          equ 1
SECBUFFER_EXTRA         equ 5
SECBUFFER_STREAM_HEADER equ 7
SECBUFFER_STREAM_TRAILER equ 6
SECBUFFER_VERSION       equ 0

;; SCHANNEL_CRED protocol flags
SP_PROT_TLS1_2_CLIENT   equ 00000800h
SP_PROT_TLS1_3_CLIENT   equ 00002000h
SP_PROT_TLS1_2_SERVER   equ 00000400h
SP_PROT_TLS1_3_SERVER   equ 00001000h

SCH_CRED_NO_DEFAULT_CREDS      equ 00000010h
SCH_CRED_MANUAL_CRED_VALIDATION equ 00000008h
SCH_USE_STRONG_CRYPTO           equ 00400000h

SCHANNEL_CRED_VERSION   equ 4

;; ---- SSPI Structures ----
SecHandle STRUCT
    dwLower DWORD ?
    dwUpper DWORD ?
SecHandle ENDS

CredHandle TYPEDEF SecHandle
CtxtHandle TYPEDEF SecHandle

SecBuffer STRUCT
    cbBuffer   DWORD ?
    BufferType DWORD ?
    pvBuffer   DWORD ?
SecBuffer ENDS

SecBufferDesc STRUCT
    ulVersion  DWORD ?
    cBuffers   DWORD ?
    pBuffers   DWORD ?
SecBufferDesc ENDS

SCHANNEL_CRED STRUCT
    dwVersion              DWORD ?
    cCreds                 DWORD ?
    paCred                 DWORD ?
    hRootStore             DWORD ?
    cMappers               DWORD ?
    aphMappers             DWORD ?
    cSupportedAlgs         DWORD ?
    palgSupportedAlgs      DWORD ?
    grbitEnabledProtocols  DWORD ?
    dwMinimumCipherStrength DWORD ?
    dwMaximumCipherStrength DWORD ?
    dwSessionLifespan      DWORD ?
    dwFlags                DWORD ?
    dwCredFormat           DWORD ?
SCHANNEL_CRED ENDS

SecPkgContext_StreamSizes STRUCT
    cbHeader        DWORD ?
    cbTrailer       DWORD ?
    cbMaximumMessage DWORD ?
    cBuffers        DWORD ?
    cbBlockSize     DWORD ?
SecPkgContext_StreamSizes ENDS

;; ---- Kernel32 prototypes needed by this module ----
IFNDEF _RTLCOPYMEMORY_DEFINED
_RTLCOPYMEMORY_DEFINED equ 1
RtlMoveMemory   PROTO :DWORD, :DWORD, :DWORD
ENDIF
IFNDEF _GLOBALALLOC_DEFINED
_GLOBALALLOC_DEFINED equ 1
GlobalAlloc     PROTO :DWORD, :DWORD
GlobalFree      PROTO :DWORD
ENDIF

;; ---- SSPI API Prototypes ----
AcquireCredentialsHandleA PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, \
                                :DWORD, :DWORD, :DWORD, :DWORD
InitializeSecurityContextA PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, \
                                 :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
AcceptSecurityContext PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, \
                            :DWORD, :DWORD, :DWORD, :DWORD
FreeContextBuffer    PROTO :DWORD
DeleteSecurityContext PROTO :DWORD
FreeCredentialsHandle PROTO :DWORD
QueryContextAttributesA PROTO :DWORD, :DWORD, :DWORD
EncryptMessage       PROTO :DWORD, :DWORD, :DWORD, :DWORD
DecryptMessage       PROTO :DWORD, :DWORD, :DWORD, :DWORD

;; Stream sizes query attribute
SECPKG_ATTR_STREAM_SIZES equ 4

;; Certificate store APIs
CertOpenStore               PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
CertCloseStore              PROTO :DWORD, :DWORD
CertFindCertificateInStore  PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
CertCreateSelfSignCertificate PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
CertAddCertificateContextToStore PROTO :DWORD, :DWORD, :DWORD, :DWORD
CertFreeCertificateContext  PROTO :DWORD

CERT_STORE_PROV_SYSTEM_A     equ 9
CERT_STORE_PROV_MEMORY       equ 2
CERT_SYSTEM_STORE_LOCAL_MACHINE equ 00020000h
CERT_SYSTEM_STORE_CURRENT_USER equ 00010000h
CERT_STORE_ADD_REPLACE_EXISTING equ 3
X509_ASN_ENCODING            equ 00000001h
PKCS_7_ASN_ENCODING          equ 00010000h
MY_ENCODING                  equ X509_ASN_ENCODING or PKCS_7_ASN_ENCODING
CERT_FIND_SUBJECT_STR_A      equ 00070004h

;; CERT_NAME_BLOB for self-signed cert
CERT_NAME_BLOB STRUCT
    cbData DWORD ?
    pbData DWORD ?
CERT_NAME_BLOB ENDS

;; CertStrToNameA
CertStrToNameA PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD

;; ---- TLS Context structure (per-connection state) ----
TLS_CTX STRUCT
    hCred      CredHandle <>
    hCtx       CtxtHandle <>
    sock       DWORD ?              ; underlying TCP socket
    bInited    DWORD ?              ; 1 = handshake complete
    bServer    DWORD ?              ; 1 = server mode
    bOwnsCred  DWORD ?              ; 1 = this ctx owns the credential (should free it)
    bPlain     DWORD ?              ; 1 = plaintext mode (no encryption)
    sizes      SecPkgContext_StreamSizes <>
    recvBuf    DWORD ?              ; GlobalAlloc'd recv buffer (encrypted)
    recvLen    DWORD ?              ; bytes in recv buffer
    recvCap    DWORD ?              ; recv buffer capacity
TLS_CTX ENDS

TLS_RECV_BUF_SIZE equ 65536         ; 64KB recv buffer

.data
    szSChannel  db "Microsoft Unified Security Protocol Provider", 0
    szCertCN    db "CN=mrsh-server", 0
    szMyStore   db "MY", 0
    szMrshCert  db "mrsh-server", 0
    X500_FLAG   equ 3   ; CERT_X500_NAME_STR
    _szTlsErrFmt db "[tls] handshake failed: SSPI=0x%08X", 13, 10, 0

LogMsg      PROTO :DWORD
wsprintfA   PROTO C :DWORD, :DWORD, :VARARG

.data?
    _hCertStore DWORD ?
    _pServerCert DWORD ?
    _szTlsErrBuf BYTE 64 dup(?)

.code

;; =============================================================================
;; _TlsGetServerCert — Get or create self-signed server certificate
;; Returns: pCertContext in eax, 0 on failure
;; =============================================================================
_TlsGetServerCert PROC
    LOCAL   nameBlob:CERT_NAME_BLOB
    LOCAL   cbEncoded:DWORD
    LOCAL   pEncoded:DWORD

    ;; Open in-memory store (no admin, ephemeral cert per session)
    invoke  CertOpenStore, CERT_STORE_PROV_MEMORY, 0, 0, 0, 0
    test    eax, eax
    jz      @gsc_fail
    mov     _hCertStore, eax

    ;; Create self-signed cert for TLS server handshake
    ;; Encode subject name "CN=mrsh-server"
    invoke  CertStrToNameA, MY_ENCODING, ADDR szCertCN, X500_FLAG, \
            0, 0, ADDR cbEncoded, 0
    test    eax, eax
    jz      @gsc_close

    invoke  GlobalAlloc, 0, cbEncoded
    test    eax, eax
    jz      @gsc_close
    mov     pEncoded, eax

    invoke  CertStrToNameA, MY_ENCODING, ADDR szCertCN, X500_FLAG, \
            0, pEncoded, ADDR cbEncoded, 0
    test    eax, eax
    jz      @gsc_free_enc

    mov     eax, cbEncoded
    mov     nameBlob.cbData, eax
    mov     eax, pEncoded
    mov     nameBlob.pbData, eax

    ;; Create self-signed cert (valid for ~1 year by default)
    invoke  CertCreateSelfSignCertificate, 0, ADDR nameBlob, 0, \
            0, 0, 0, 0, 0
    test    eax, eax
    jz      @gsc_free_enc

    ;; CertCreateSelfSignCertificate returns a cert context we can use directly
    ;; No need to add to store — SChannel accepts any valid PCCERT_CONTEXT
    mov     _pServerCert, eax
    invoke  GlobalFree, pEncoded
    mov     eax, _pServerCert
    ret

@gsc_free_enc:
    invoke  GlobalFree, pEncoded
@gsc_close:
    invoke  CertCloseStore, _hCertStore, 0
@gsc_fail:
    xor     eax, eax
    ret
_TlsGetServerCert ENDP

;; =============================================================================
;; TlsInit — Initialize SChannel credentials
;; Args: pCtx (ptr to TLS_CTX), bServerMode (0=client, 1=server)
;; Returns: 0 = success, -1 = error
;; =============================================================================
TlsInit PROC pCtx:DWORD, bServerMode:DWORD
    LOCAL   schCred:SCHANNEL_CRED
    LOCAL   credUse:DWORD

    invoke  RtlZeroMemory, pCtx, SIZEOF TLS_CTX
    invoke  RtlZeroMemory, ADDR schCred, SIZEOF SCHANNEL_CRED

    mov     schCred.dwVersion, SCHANNEL_CRED_VERSION

    ;; Set protocol + flags based on client/server mode
    cmp     bServerMode, 0
    jne     @tls_server

    ;; Client: TLS 1.2 + 1.3, manual cert validation (TOFU)
    mov     schCred.grbitEnabledProtocols, SP_PROT_TLS1_2_CLIENT or SP_PROT_TLS1_3_CLIENT
    mov     schCred.dwFlags, SCH_CRED_NO_DEFAULT_CREDS or SCH_CRED_MANUAL_CRED_VALIDATION or SCH_USE_STRONG_CRYPTO
    mov     credUse, SECPKG_CRED_OUTBOUND
    jmp     @tls_acquire

@tls_server:
    ;; Get or create server certificate
    invoke  _TlsGetServerCert
    test    eax, eax
    jz      @tls_init_fail

    ;; Set cert in SCHANNEL_CRED: cCreds=1, paCred=&pServerCert
    mov     schCred.cCreds, 1
    lea     eax, _pServerCert
    mov     schCred.paCred, eax
    mov     schCred.grbitEnabledProtocols, SP_PROT_TLS1_2_SERVER or SP_PROT_TLS1_3_SERVER
    mov     schCred.dwFlags, SCH_USE_STRONG_CRYPTO
    mov     credUse, SECPKG_CRED_INBOUND

    ;; Store server mode flag
    mov     edx, pCtx
    mov     (TLS_CTX PTR [edx]).bServer, 1

@tls_acquire:
    ;; AcquireCredentialsHandle
    mov     edx, pCtx
    lea     eax, (TLS_CTX PTR [edx]).hCred
    invoke  AcquireCredentialsHandleA, \
            NULL,               \   ; pszPrincipal
            ADDR szSChannel,    \   ; pszPackage
            credUse,            \   ; fCredentialUse
            NULL,               \   ; pvLogonID
            ADDR schCred,       \   ; pAuthData
            NULL,               \   ; pGetKeyFn
            NULL,               \   ; pvGetKeyArgument
            eax,                \   ; phCredential (output)
            NULL                    ; ptsExpiry

    cmp     eax, SEC_E_OK
    jne     @tls_init_fail

    ;; Allocate recv buffer
    invoke  GlobalAlloc, 0, TLS_RECV_BUF_SIZE
    test    eax, eax
    jz      @tls_init_fail

    mov     edx, pCtx
    mov     (TLS_CTX PTR [edx]).recvBuf, eax
    mov     (TLS_CTX PTR [edx]).recvCap, TLS_RECV_BUF_SIZE
    mov     (TLS_CTX PTR [edx]).recvLen, 0

    mov     edx, pCtx
    mov     (TLS_CTX PTR [edx]).bOwnsCred, 1    ; this ctx owns the credential

    xor     eax, eax
    ret

@tls_init_fail:
    mov     eax, -1
    ret
TlsInit ENDP

;; =============================================================================
;; TlsConnect — Perform TLS handshake (client)
;; Args: pCtx, sock (connected TCP socket), lpServerName (for SNI)
;; Returns: 0 = success, -1 = error
;; =============================================================================
TlsConnect PROC uses ebx esi edi pCtx:DWORD, nSock:DWORD, lpServerName:DWORD
    LOCAL   outBufDesc:SecBufferDesc
    LOCAL   outBuf:SecBuffer
    LOCAL   inBufDesc:SecBufferDesc
    LOCAL   inBufs[2]:SecBuffer
    LOCAL   dwSSPIFlags:DWORD
    LOCAL   dwSSPIOutFlags:DWORD
    LOCAL   pCtxIn:DWORD
    LOCAL   cbData:DWORD

    ;; Store socket in context
    mov     edx, pCtx
    mov     eax, nSock
    mov     (TLS_CTX PTR [edx]).sock, eax

    mov     dwSSPIFlags, ISC_REQ_FLAGS
    mov     pCtxIn, NULL            ; first call: NULL context

    ;; ---- First ISC call (no input token) ----
    mov     outBuf.cbBuffer, 0
    mov     outBuf.BufferType, SECBUFFER_TOKEN
    mov     outBuf.pvBuffer, NULL
    mov     outBufDesc.ulVersion, SECBUFFER_VERSION
    mov     outBufDesc.cBuffers, 1
    lea     eax, outBuf
    mov     outBufDesc.pBuffers, eax

    mov     edx, pCtx
    lea     esi, (TLS_CTX PTR [edx]).hCred
    lea     edi, (TLS_CTX PTR [edx]).hCtx

    invoke  InitializeSecurityContextA, \
            esi, NULL, lpServerName, \
            dwSSPIFlags, 0, 0, NULL, 0, \
            edi, ADDR outBufDesc, \
            ADDR dwSSPIOutFlags, NULL

    cmp     eax, SEC_I_CONTINUE_NEEDED
    jne     @hs_fail

    ;; Send initial token to server
    cmp     outBuf.cbBuffer, 0
    je      @hs_loop
    invoke  NetSendAll, nSock, outBuf.pvBuffer, outBuf.cbBuffer
    invoke  FreeContextBuffer, outBuf.pvBuffer
    test    eax, eax

    ;; ---- Handshake loop ----
@hs_loop:
    ;; Receive server response
    mov     edx, pCtx
    mov     ebx, (TLS_CTX PTR [edx]).recvBuf
    mov     ecx, (TLS_CTX PTR [edx]).recvLen

    ;; Read more data from socket into recv buffer
    mov     eax, TLS_RECV_BUF_SIZE
    sub     eax, ecx
    push    ecx
    add     ebx, ecx
    invoke  NetRecv, nSock, ebx, eax
    pop     ecx
    cmp     eax, SOCKET_ERROR
    je      @hs_fail
    cmp     eax, 0
    jle     @hs_fail
    add     ecx, eax

    ;; Store updated length
    mov     edx, pCtx
    mov     (TLS_CTX PTR [edx]).recvLen, ecx

    ;; Setup input buffers
    mov     edx, pCtx
    mov     eax, (TLS_CTX PTR [edx]).recvBuf
    mov     inBufs[0 * SIZEOF SecBuffer].pvBuffer, eax
    mov     inBufs[0 * SIZEOF SecBuffer].cbBuffer, ecx
    mov     inBufs[0 * SIZEOF SecBuffer].BufferType, SECBUFFER_TOKEN
    mov     inBufs[1 * SIZEOF SecBuffer].pvBuffer, NULL
    mov     inBufs[1 * SIZEOF SecBuffer].cbBuffer, 0
    mov     inBufs[1 * SIZEOF SecBuffer].BufferType, SECBUFFER_EMPTY
    mov     inBufDesc.ulVersion, SECBUFFER_VERSION
    mov     inBufDesc.cBuffers, 2
    lea     eax, inBufs
    mov     inBufDesc.pBuffers, eax

    ;; Setup output buffer
    mov     outBuf.cbBuffer, 0
    mov     outBuf.BufferType, SECBUFFER_TOKEN
    mov     outBuf.pvBuffer, NULL
    mov     outBufDesc.ulVersion, SECBUFFER_VERSION
    mov     outBufDesc.cBuffers, 1
    lea     eax, outBuf
    mov     outBufDesc.pBuffers, eax

    mov     edx, pCtx
    lea     esi, (TLS_CTX PTR [edx]).hCred
    lea     edi, (TLS_CTX PTR [edx]).hCtx

    invoke  InitializeSecurityContextA, \
            esi, edi, lpServerName, \
            dwSSPIFlags, 0, 0, \
            ADDR inBufDesc, 0, \
            NULL, ADDR outBufDesc, \
            ADDR dwSSPIOutFlags, NULL

    mov     cbData, eax             ; save status

    ;; Send output token if any
    cmp     outBuf.cbBuffer, 0
    je      @hs_no_send
    push    eax
    invoke  NetSendAll, nSock, outBuf.pvBuffer, outBuf.cbBuffer
    invoke  FreeContextBuffer, outBuf.pvBuffer
    pop     eax
@hs_no_send:

    ;; Handle extra data (move to beginning of recv buffer)
    cmp     inBufs[1 * SIZEOF SecBuffer].BufferType, SECBUFFER_EXTRA
    jne     @hs_no_extra
    mov     ecx, inBufs[1 * SIZEOF SecBuffer].cbBuffer
    mov     edx, pCtx
    mov     esi, (TLS_CTX PTR [edx]).recvBuf
    mov     edi, (TLS_CTX PTR [edx]).recvLen
    sub     edi, ecx                ; offset of extra data
    add     esi, edi                ; source
    mov     edx, pCtx
    mov     edi, (TLS_CTX PTR [edx]).recvBuf  ; destination
    invoke  RtlMoveMemory, edi, esi, ecx
    mov     edx, pCtx
    mov     (TLS_CTX PTR [edx]).recvLen, ecx
    jmp     @hs_check_status
@hs_no_extra:
    mov     edx, pCtx
    mov     (TLS_CTX PTR [edx]).recvLen, 0

@hs_check_status:
    mov     eax, cbData
    cmp     eax, SEC_I_CONTINUE_NEEDED
    je      @hs_loop
    cmp     eax, SEC_E_INCOMPLETE_MESSAGE
    je      @hs_loop
    cmp     eax, SEC_E_OK
    jne     @hs_fail

    ;; ---- Handshake complete ----
    ;; Query stream sizes for encrypt/decrypt
    mov     edx, pCtx
    lea     esi, (TLS_CTX PTR [edx]).hCtx
    lea     edi, (TLS_CTX PTR [edx]).sizes
    invoke  QueryContextAttributesA, esi, SECPKG_ATTR_STREAM_SIZES, edi

    mov     edx, pCtx
    mov     (TLS_CTX PTR [edx]).bInited, 1

    xor     eax, eax
    ret

@hs_fail:
    ;; Debug: log SSPI error code only if verbose (-v flag)
    cmp     cliArgs.bVerbose, 0
    je      @hs_fail_quiet
    push    cbData
    lea     eax, _szTlsErrFmt
    push    eax
    lea     eax, _szTlsErrBuf
    push    eax
    call    wsprintfA
    add     esp, 12
    invoke  LogMsg, ADDR _szTlsErrBuf
@hs_fail_quiet:
    mov     eax, -1
    ret
TlsConnect ENDP

;; =============================================================================
;; TlsAccept — Server-side TLS handshake
;; Args: pCtx (initialized with bServer=1), nSock
;; Returns: 0 = success, -1 = error
;; =============================================================================
TlsAccept PROC uses ebx esi edi pCtx:DWORD, nSock:DWORD
    LOCAL   outBufDesc:SecBufferDesc
    LOCAL   outBuf:SecBuffer
    LOCAL   inBufDesc:SecBufferDesc
    LOCAL   inBufs[2]:SecBuffer
    LOCAL   dwSSPIFlags:DWORD
    LOCAL   dwSSPIOutFlags:DWORD
    LOCAL   cbData:DWORD
    LOCAL   bFirstCall:DWORD

    mov     edx, pCtx
    mov     eax, nSock
    mov     (TLS_CTX PTR [edx]).sock, eax
    mov     dwSSPIFlags, ASC_REQ_FLAGS
    mov     bFirstCall, 1

@ta_loop:
    ;; Read client data
    mov     edx, pCtx
    mov     esi, (TLS_CTX PTR [edx]).recvBuf
    mov     ecx, (TLS_CTX PTR [edx]).recvLen
    mov     eax, TLS_RECV_BUF_SIZE
    sub     eax, ecx
    push    ecx
    add     esi, ecx
    invoke  NetRecv, nSock, esi, eax
    pop     ecx
    cmp     eax, SOCKET_ERROR
    je      @ta_fail
    cmp     eax, 0
    jle     @ta_fail
    add     ecx, eax
    mov     edx, pCtx
    mov     (TLS_CTX PTR [edx]).recvLen, ecx

    ;; Setup input
    mov     edx, pCtx
    mov     eax, (TLS_CTX PTR [edx]).recvBuf
    mov     inBufs[0 * SIZEOF SecBuffer].pvBuffer, eax
    mov     inBufs[0 * SIZEOF SecBuffer].cbBuffer, ecx
    mov     inBufs[0 * SIZEOF SecBuffer].BufferType, SECBUFFER_TOKEN
    mov     inBufs[1 * SIZEOF SecBuffer].pvBuffer, NULL
    mov     inBufs[1 * SIZEOF SecBuffer].cbBuffer, 0
    mov     inBufs[1 * SIZEOF SecBuffer].BufferType, SECBUFFER_EMPTY
    mov     inBufDesc.ulVersion, SECBUFFER_VERSION
    mov     inBufDesc.cBuffers, 2
    lea     eax, inBufs
    mov     inBufDesc.pBuffers, eax

    ;; Setup output
    mov     outBuf.cbBuffer, 0
    mov     outBuf.BufferType, SECBUFFER_TOKEN
    mov     outBuf.pvBuffer, NULL
    mov     outBufDesc.ulVersion, SECBUFFER_VERSION
    mov     outBufDesc.cBuffers, 1
    lea     eax, outBuf
    mov     outBufDesc.pBuffers, eax

    mov     edx, pCtx
    lea     esi, (TLS_CTX PTR [edx]).hCred
    lea     edi, (TLS_CTX PTR [edx]).hCtx

    ;; AcceptSecurityContext
    cmp     bFirstCall, 1
    jne     @ta_subsequent
    invoke  AcceptSecurityContext, \
            esi, NULL, ADDR inBufDesc, \
            dwSSPIFlags, 0, \
            edi, ADDR outBufDesc, \
            ADDR dwSSPIOutFlags, NULL
    mov     bFirstCall, 0
    jmp     @ta_check
@ta_subsequent:
    invoke  AcceptSecurityContext, \
            esi, edi, ADDR inBufDesc, \
            dwSSPIFlags, 0, \
            NULL, ADDR outBufDesc, \
            ADDR dwSSPIOutFlags, NULL

@ta_check:
    mov     cbData, eax

    ;; Send output token if any
    cmp     outBuf.cbBuffer, 0
    je      @ta_no_send
    push    eax
    invoke  NetSendAll, nSock, outBuf.pvBuffer, outBuf.cbBuffer
    invoke  FreeContextBuffer, outBuf.pvBuffer
    pop     eax
@ta_no_send:

    ;; Handle extra data
    cmp     inBufs[1 * SIZEOF SecBuffer].BufferType, SECBUFFER_EXTRA
    jne     @ta_no_extra
    mov     ecx, inBufs[1 * SIZEOF SecBuffer].cbBuffer
    mov     edx, pCtx
    mov     esi, (TLS_CTX PTR [edx]).recvBuf
    mov     edi, (TLS_CTX PTR [edx]).recvLen
    sub     edi, ecx
    add     esi, edi
    mov     edx, pCtx
    mov     edi, (TLS_CTX PTR [edx]).recvBuf
    invoke  RtlMoveMemory, edi, esi, ecx
    mov     edx, pCtx
    mov     (TLS_CTX PTR [edx]).recvLen, ecx
    jmp     @ta_status
@ta_no_extra:
    mov     edx, pCtx
    mov     (TLS_CTX PTR [edx]).recvLen, 0

@ta_status:
    mov     eax, cbData
    cmp     eax, SEC_I_CONTINUE_NEEDED
    je      @ta_loop
    cmp     eax, SEC_E_INCOMPLETE_MESSAGE
    je      @ta_loop
    cmp     eax, SEC_E_OK
    jne     @ta_fail

    ;; Handshake complete — query stream sizes
    mov     edx, pCtx
    lea     esi, (TLS_CTX PTR [edx]).hCtx
    lea     edi, (TLS_CTX PTR [edx]).sizes
    invoke  QueryContextAttributesA, esi, SECPKG_ATTR_STREAM_SIZES, edi
    mov     edx, pCtx
    mov     (TLS_CTX PTR [edx]).bInited, 1

    xor     eax, eax
    ret

@ta_fail:
    mov     eax, -1
    ret
TlsAccept ENDP

;; =============================================================================
;; TlsSend — Encrypt and send data over TLS
;; Args: pCtx, lpBuf, nLen
;; Returns: 0 = success, -1 = error
;; =============================================================================
TlsSend PROC uses ebx esi edi pCtx:DWORD, lpBuf:DWORD, nLen:DWORD
    LOCAL   msgBufDesc:SecBufferDesc
    LOCAL   msgBufs[4]:SecBuffer
    LOCAL   pIoBuf:DWORD
    LOCAL   cbIoBuf:DWORD

    ;; Plaintext passthrough
    mov     edx, pCtx
    cmp     (TLS_CTX PTR [edx]).bPlain, 1
    jne     @ts_encrypted
    mov     eax, (TLS_CTX PTR [edx]).sock
    invoke  NetSendAll, eax, lpBuf, nLen
    ret
@ts_encrypted:

    mov     edx, pCtx
    mov     eax, (TLS_CTX PTR [edx]).sizes.cbHeader
    add     eax, nLen
    add     eax, (TLS_CTX PTR [edx]).sizes.cbTrailer
    mov     cbIoBuf, eax

    invoke  GlobalAlloc, 0, cbIoBuf
    test    eax, eax
    jz      @ts_fail
    mov     pIoBuf, eax

    ;; Copy plaintext after header space
    mov     edx, pCtx
    mov     ecx, (TLS_CTX PTR [edx]).sizes.cbHeader
    mov     edi, pIoBuf
    add     edi, ecx
    invoke  RtlMoveMemory, edi, lpBuf, nLen

    ;; Setup 4 buffers: header, data, trailer, empty
    mov     edx, pCtx
    ;; Buffer 0: header
    mov     eax, pIoBuf
    mov     msgBufs[0 * SIZEOF SecBuffer].pvBuffer, eax
    mov     eax, (TLS_CTX PTR [edx]).sizes.cbHeader
    mov     msgBufs[0 * SIZEOF SecBuffer].cbBuffer, eax
    mov     msgBufs[0 * SIZEOF SecBuffer].BufferType, SECBUFFER_STREAM_HEADER
    ;; Buffer 1: data
    mov     eax, pIoBuf
    add     eax, (TLS_CTX PTR [edx]).sizes.cbHeader
    mov     msgBufs[1 * SIZEOF SecBuffer].pvBuffer, eax
    mov     eax, nLen
    mov     msgBufs[1 * SIZEOF SecBuffer].cbBuffer, eax
    mov     msgBufs[1 * SIZEOF SecBuffer].BufferType, SECBUFFER_DATA
    ;; Buffer 2: trailer
    mov     eax, pIoBuf
    add     eax, (TLS_CTX PTR [edx]).sizes.cbHeader
    add     eax, nLen
    mov     msgBufs[2 * SIZEOF SecBuffer].pvBuffer, eax
    mov     eax, (TLS_CTX PTR [edx]).sizes.cbTrailer
    mov     msgBufs[2 * SIZEOF SecBuffer].cbBuffer, eax
    mov     msgBufs[2 * SIZEOF SecBuffer].BufferType, SECBUFFER_STREAM_TRAILER
    ;; Buffer 3: empty
    mov     msgBufs[3 * SIZEOF SecBuffer].pvBuffer, NULL
    mov     msgBufs[3 * SIZEOF SecBuffer].cbBuffer, 0
    mov     msgBufs[3 * SIZEOF SecBuffer].BufferType, SECBUFFER_EMPTY

    mov     msgBufDesc.ulVersion, SECBUFFER_VERSION
    mov     msgBufDesc.cBuffers, 4
    lea     eax, msgBufs
    mov     msgBufDesc.pBuffers, eax

    ;; Encrypt
    mov     edx, pCtx
    lea     esi, (TLS_CTX PTR [edx]).hCtx
    invoke  EncryptMessage, esi, 0, ADDR msgBufDesc, 0
    cmp     eax, SEC_E_OK
    jne     @ts_free

    ;; Total encrypted size = header + data + trailer
    mov     eax, msgBufs[0 * SIZEOF SecBuffer].cbBuffer
    add     eax, msgBufs[1 * SIZEOF SecBuffer].cbBuffer
    add     eax, msgBufs[2 * SIZEOF SecBuffer].cbBuffer

    ;; Send all encrypted data
    mov     edx, pCtx
    invoke  NetSendAll, (TLS_CTX PTR [edx]).sock, pIoBuf, eax
    push    eax
    invoke  GlobalFree, pIoBuf
    pop     eax
    ret

@ts_free:
    invoke  GlobalFree, pIoBuf
@ts_fail:
    mov     eax, -1
    ret
TlsSend ENDP

;; =============================================================================
;; TlsRecv — Receive and decrypt data from TLS
;; Args: pCtx, lpBuf (output buffer), nBufSize
;; Returns: bytes decrypted, 0 = closed, -1 = error
;; =============================================================================
TlsRecv PROC uses ebx esi edi pCtx:DWORD, lpBuf:DWORD, nBufSize:DWORD
    LOCAL   msgBufDesc:SecBufferDesc
    LOCAL   msgBufs[4]:SecBuffer
    LOCAL   cbData:DWORD

    ;; Plaintext passthrough
    mov     edx, pCtx
    cmp     (TLS_CTX PTR [edx]).bPlain, 1
    jne     @tr_encrypted
    mov     eax, (TLS_CTX PTR [edx]).sock
    invoke  NetRecv, eax, lpBuf, nBufSize
    ret
@tr_encrypted:

@tr_read:
    ;; Try to decrypt what we have in the recv buffer
    mov     edx, pCtx
    cmp     (TLS_CTX PTR [edx]).recvLen, 0
    je      @tr_need_more

    ;; Setup decrypt buffers
    mov     edx, pCtx
    mov     eax, (TLS_CTX PTR [edx]).recvBuf
    mov     ecx, (TLS_CTX PTR [edx]).recvLen
    mov     msgBufs[0 * SIZEOF SecBuffer].pvBuffer, eax
    mov     msgBufs[0 * SIZEOF SecBuffer].cbBuffer, ecx
    mov     msgBufs[0 * SIZEOF SecBuffer].BufferType, SECBUFFER_DATA
    mov     msgBufs[1 * SIZEOF SecBuffer].BufferType, SECBUFFER_EMPTY
    mov     msgBufs[1 * SIZEOF SecBuffer].cbBuffer, 0
    mov     msgBufs[1 * SIZEOF SecBuffer].pvBuffer, NULL
    mov     msgBufs[2 * SIZEOF SecBuffer].BufferType, SECBUFFER_EMPTY
    mov     msgBufs[2 * SIZEOF SecBuffer].cbBuffer, 0
    mov     msgBufs[2 * SIZEOF SecBuffer].pvBuffer, NULL
    mov     msgBufs[3 * SIZEOF SecBuffer].BufferType, SECBUFFER_EMPTY
    mov     msgBufs[3 * SIZEOF SecBuffer].cbBuffer, 0
    mov     msgBufs[3 * SIZEOF SecBuffer].pvBuffer, NULL

    mov     msgBufDesc.ulVersion, SECBUFFER_VERSION
    mov     msgBufDesc.cBuffers, 4
    lea     eax, msgBufs
    mov     msgBufDesc.pBuffers, eax

    mov     edx, pCtx
    lea     esi, (TLS_CTX PTR [edx]).hCtx
    invoke  DecryptMessage, esi, ADDR msgBufDesc, 0, NULL

    cmp     eax, SEC_E_OK
    je      @tr_decrypted
    cmp     eax, SEC_E_INCOMPLETE_MESSAGE
    je      @tr_need_more
    cmp     eax, SEC_I_CONTEXT_EXPIRED
    je      @tr_closed
    cmp     eax, SEC_I_RENEGOTIATE
    je      @tr_fail    ; TODO: handle renegotiation
    jmp     @tr_fail

@tr_decrypted:
    ;; Find the DATA buffer — scan 4 SecBuffers (12 bytes each)
    ;; SecBuffer = { cbBuffer:4, BufferType:4, pvBuffer:4 }
    lea     ebx, msgBufs
    mov     ecx, 4                  ; counter
@tr_find_data:
    cmp     ecx, 0
    jle     @tr_fail
    cmp     dword ptr [ebx + 4], SECBUFFER_DATA   ; BufferType offset = 4
    je      @tr_found_data
    add     ebx, SIZEOF SecBuffer   ; next buffer (12 bytes)
    dec     ecx
    jmp     @tr_find_data

@tr_found_data:
    ;; ebx points to the DATA SecBuffer — return ALL decrypted data
    ;; Caller must provide a buffer large enough (TlsRecvLenPrefixed uses 64KB)
    mov     ecx, dword ptr [ebx]            ; cbBuffer (full decrypted size)
    cmp     ecx, nBufSize
    jle     @tr_copy
    mov     ecx, nBufSize                   ; safety cap (shouldn't happen with proper callers)
@tr_copy:
    mov     cbData, ecx
    mov     esi, dword ptr [ebx + 8]        ; pvBuffer
    invoke  RtlMoveMemory, lpBuf, esi, cbData

    ;; Find EXTRA buffer (leftover encrypted data)
    mov     edx, pCtx
    mov     (TLS_CTX PTR [edx]).recvLen, 0
    lea     ebx, msgBufs
    mov     ecx, 4
@tr_find_extra:
    cmp     ecx, 0
    jle     @tr_return
    cmp     dword ptr [ebx + 4], SECBUFFER_EXTRA
    je      @tr_has_extra
    add     ebx, SIZEOF SecBuffer
    dec     ecx
    jmp     @tr_find_extra
@tr_has_extra:
    mov     ecx, dword ptr [ebx]            ; cbBuffer
    mov     esi, dword ptr [ebx + 8]        ; pvBuffer
    mov     edx, pCtx
    mov     edi, (TLS_CTX PTR [edx]).recvBuf
    invoke  RtlMoveMemory, edi, esi, ecx
    mov     edx, pCtx
    mov     (TLS_CTX PTR [edx]).recvLen, ecx

@tr_return:
    mov     eax, cbData
    ret

@tr_need_more:
    ;; Read more from socket
    mov     edx, pCtx
    mov     esi, (TLS_CTX PTR [edx]).recvBuf
    mov     ecx, (TLS_CTX PTR [edx]).recvLen
    add     esi, ecx
    mov     eax, (TLS_CTX PTR [edx]).recvCap
    sub     eax, ecx            ; space remaining
    cmp     eax, 0
    jle     @tr_fail            ; buffer full

    mov     edx, pCtx
    invoke  NetRecv, (TLS_CTX PTR [edx]).sock, esi, eax
    cmp     eax, SOCKET_ERROR
    je      @tr_fail
    cmp     eax, 0
    jle     @tr_closed

    mov     edx, pCtx
    add     (TLS_CTX PTR [edx]).recvLen, eax
    jmp     @tr_read

@tr_closed:
    xor     eax, eax
    ret

@tr_fail:
    mov     eax, -1
    ret
TlsRecv ENDP

;; =============================================================================
;; TlsClose — Shutdown TLS + free resources
;; =============================================================================
TlsClose PROC pCtx:DWORD
    mov     edx, pCtx
    cmp     (TLS_CTX PTR [edx]).bInited, 0
    je      @tc_free

    ;; Delete security context
    mov     edx, pCtx
    lea     eax, (TLS_CTX PTR [edx]).hCtx
    invoke  DeleteSecurityContext, eax

@tc_free:
    ;; Free credentials only if this context owns them
    mov     edx, pCtx
    cmp     (TLS_CTX PTR [edx]).bOwnsCred, 1
    jne     @tc_buf
    lea     eax, (TLS_CTX PTR [edx]).hCred
    invoke  FreeCredentialsHandle, eax
@tc_buf:

    ;; Free recv buffer
    mov     edx, pCtx
    mov     eax, (TLS_CTX PTR [edx]).recvBuf
    test    eax, eax
    jz      @tc_done
    invoke  GlobalFree, eax

@tc_done:
    invoke  RtlZeroMemory, pCtx, SIZEOF TLS_CTX
    ret
TlsClose ENDP

;; =============================================================================
;; TlsSendLenPrefixed — Send length-prefixed message over TLS
;; =============================================================================
TlsSendLenPrefixed PROC uses esi edi pCtx:DWORD, lpBuf:DWORD, nLen:DWORD
    LOCAL   pCombined:DWORD
    LOCAL   cbCombined:DWORD

    ;; Combine [4-byte BE length][payload] into single buffer → single TLS record
    mov     eax, nLen
    add     eax, 4
    mov     cbCombined, eax
    invoke  GlobalAlloc, 0, cbCombined
    test    eax, eax
    jz      @tslp_err
    mov     pCombined, eax

    ;; Write length header (4 bytes big-endian) — Rust mrsh wire compat
    mov     eax, nLen
    bswap   eax
    mov     edx, pCombined
    mov     [edx], eax

    ;; Copy payload after header
    mov     edi, pCombined
    add     edi, 4
    invoke  RtlMoveMemory, edi, lpBuf, nLen

    ;; Single TlsSend → single encrypted TLS record
    invoke  TlsSend, pCtx, pCombined, cbCombined
    push    eax
    invoke  GlobalFree, pCombined
    pop     eax
    ret

@tslp_err:
    mov     eax, -1
    ret
TlsSendLenPrefixed ENDP

;; =============================================================================
;; TlsRecvLenPrefixed — Receive length-prefixed message over TLS
;; Caller must GlobalFree the buffer
;; =============================================================================
TlsRecvLenPrefixed PROC uses ebx esi edi pCtx:DWORD, lpBufOut:DWORD, lpLenOut:DWORD
    LOCAL   msgLen:DWORD
    LOCAL   pBuf:DWORD
    LOCAL   pRecv:DWORD
    LOCAL   nRecv:DWORD
    LOCAL   total:DWORD

    ;; Allocate large receive buffer (full TLS record may contain header+payload)
    invoke  GlobalAlloc, 0, TLS_RECV_BUF_SIZE
    test    eax, eax
    jz      @trlp_err
    mov     pRecv, eax

    ;; Read first TLS record — may contain length header + some/all payload
    invoke  TlsRecv, pCtx, pRecv, TLS_RECV_BUF_SIZE
    cmp     eax, 4
    jl      @trlp_free_recv
    mov     nRecv, eax

    ;; Parse 4-byte big-endian length from beginning
    mov     edx, pRecv
    mov     eax, [edx]
    bswap   eax
    mov     msgLen, eax
    cmp     msgLen, 50000000
    ja      @trlp_free_recv
    cmp     msgLen, 0
    je      @trlp_free_recv

    ;; Allocate output buffer
    invoke  GlobalAlloc, 0, msgLen
    test    eax, eax
    jz      @trlp_free_recv
    mov     pBuf, eax

    ;; Copy available payload (nRecv - 4 bytes already have data)
    mov     ebx, nRecv
    sub     ebx, 4              ; bytes of payload available
    cmp     ebx, 0
    jle     @trlp_read_more_init
    cmp     ebx, msgLen
    jle     @trlp_copy_first
    mov     ebx, msgLen         ; cap at msgLen
@trlp_copy_first:
    mov     esi, pRecv
    add     esi, 4              ; skip length header
    invoke  RtlMoveMemory, pBuf, esi, ebx
    mov     total, ebx
    invoke  GlobalFree, pRecv
    jmp     @trlp_check

@trlp_read_more_init:
    invoke  GlobalFree, pRecv
    mov     total, 0

    ;; Read remaining payload if needed
@trlp_check:
    mov     eax, total
    cmp     eax, msgLen
    jge     @trlp_done

    mov     ecx, msgLen
    sub     ecx, total
    mov     edx, pBuf
    add     edx, total
    invoke  TlsRecv, pCtx, edx, ecx
    cmp     eax, 0
    jle     @trlp_free_buf
    add     total, eax
    jmp     @trlp_check

@trlp_done:
    mov     edx, lpBufOut
    mov     eax, pBuf
    mov     [edx], eax
    mov     edx, lpLenOut
    mov     eax, msgLen
    mov     [edx], eax
    xor     eax, eax
    ret

@trlp_free_buf:
    invoke  GlobalFree, pBuf
    jmp     @trlp_err
@trlp_free_recv:
    invoke  GlobalFree, pRecv
@trlp_err:
    mov     eax, -1
    ret
TlsRecvLenPrefixed ENDP
