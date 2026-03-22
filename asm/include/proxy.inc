;; =============================================================================
;; proxy.inc — ProxyJump: tunnel through intermediate host
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; Client: connect to proxy, send CMD_PROXY_CONNECT(target), receive CMD_PROXY_OK
;; Server: receive CMD_PROXY_CONNECT, connect to target, forward bidirectionally
;; After tunnel established, client sends commands as if directly connected.
;; =============================================================================

Sleep           PROTO :DWORD
CreateThread    PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
WaitForSingleObject PROTO :DWORD, :DWORD

IFNDEF DEFAULT_PORT
DEFAULT_PORT    equ 8822
ENDIF
IFNDEF ALT_PORT
ALT_PORT        equ 9822
ENDIF

PROXY_FWD_BUF   equ 16384      ; 16KB forwarding buffer

;; Forward declarations
_ProxyFwdThread PROTO :DWORD
_ProxyForward   PROTO :DWORD, :DWORD, :DWORD

IFNDEF _GLOBALALLOC_DEFINED
_GLOBALALLOC_DEFINED equ 1
GlobalAlloc     PROTO :DWORD, :DWORD
GlobalFree      PROTO :DWORD
ENDIF
IFNDEF _RTLZEROMEMORY_DEFINED
_RTLZEROMEMORY_DEFINED equ 1
RtlZeroMemory   PROTO :DWORD, :DWORD
ENDIF

;; ---- Forwarding context (passed to relay threads) ----
PROXY_FWD_CTX STRUCT
    pSrc        DWORD ?     ; source TLS_CTX ptr
    pDst        DWORD ?     ; destination TLS_CTX ptr
    bDone       DWORD ?     ; set to 1 when either direction closes
PROXY_FWD_CTX ENDS

.data
    _szProxyConn    db "[proxy] connecting to target: ", 0
    _szProxyOk      db "[proxy] tunnel established", 13, 10, 0
    _szProxyFail    db "[proxy] connection to target failed", 0
    _szProxyEnd     db "[proxy] tunnel closed", 13, 10, 0

.data?
    _proxyFwdCtx    PROXY_FWD_CTX <>

.code

;; =============================================================================
;; ProxyHandleServer — Server-side: receive PROXY_CONNECT, tunnel to target
;; Args: pTlsCtx (client TLS), pMsg (CMD_PROXY_CONNECT message)
;; Payload: encode_str(target_host) + optional u16be(port)
;; Does NOT return until tunnel closes.
;; =============================================================================
ProxyHandleServer PROC uses ebx esi edi \
    pTlsCtx:DWORD, pMsg:DWORD

    LOCAL   targetTls:TLS_CTX
    LOCAL   targetSock:DWORD
    LOCAL   wTargetPort:WORD
    LOCAL   hFwdThread:DWORD

    ;; Parse target host from payload
    mov     edx, pMsg
    mov     esi, (MRSH_MSG PTR [edx]).pData
    movzx   eax, byte ptr [esi]
    shl     eax, 8
    movzx   ecx, byte ptr [esi + 1]
    or      eax, ecx                 ; eax = host string length
    add     esi, 2                   ; esi = host string
    mov     byte ptr [esi + eax], 0  ; null-terminate
    push    esi                      ; save host ptr

    ;; Check if port follows (payload > 2 + hostLen)
    mov     edx, pMsg
    mov     ecx, (MRSH_MSG PTR [edx]).dataLen
    sub     ecx, 2
    sub     ecx, eax                 ; remaining bytes after host
    cmp     ecx, 2
    jb      @phs_default_port
    ;; Read port (2-byte BE)
    add     esi, eax
    movzx   eax, byte ptr [esi]
    shl     eax, 8
    movzx   ecx, byte ptr [esi + 1]
    or      eax, ecx
    mov     wTargetPort, ax
    jmp     @phs_connect
@phs_default_port:
    mov     wTargetPort, DEFAULT_PORT

@phs_connect:
    pop     esi                      ; host ptr

    ;; Connect to target (try default port → alt port → SSH port)
    invoke  NetConnect, esi, wTargetPort
    cmp     eax, INVALID_SOCKET
    jne     @phs_connected
    ;; Try alt port if default was used
    cmp     wTargetPort, DEFAULT_PORT
    jne     @phs_conn_fail
    invoke  NetConnect, esi, ALT_PORT
    cmp     eax, INVALID_SOCKET
    jne     @phs_connected
    jmp     @phs_conn_fail

@phs_connected:
    mov     targetSock, eax
    invoke  NetSetTimeout, eax, 30000

    ;; TLS handshake to target
    invoke  RtlZeroMemory, ADDR targetTls, SIZEOF TLS_CTX
    mov     eax, targetSock
    mov     targetTls.sock, eax
    invoke  TlsInit, ADDR targetTls, 0
    test    eax, eax
    jnz     @phs_close_target
    mov     eax, targetSock
    mov     targetTls.sock, eax
    invoke  TlsConnect, ADDR targetTls, targetSock, esi
    test    eax, eax
    jnz     @phs_close_target

    ;; Auth with target
    invoke  AuthClientHandshake, ADDR targetTls
    test    eax, eax
    jnz     @phs_close_tls

    ;; Send PROXY_OK to client
    invoke  LogMsg, ADDR _szProxyOk
    invoke  ProtoSendMsg, pTlsCtx, CMD_PROXY_OK, 0, 0

    ;; Setup bidirectional forwarding
    ;; Thread 1 (this thread): client → target
    ;; Thread 2 (new thread): target → client
    lea     eax, targetTls
    mov     _proxyFwdCtx.pSrc, eax
    mov     eax, pTlsCtx
    mov     _proxyFwdCtx.pDst, eax
    mov     _proxyFwdCtx.bDone, 0

    ;; Start target→client forwarding thread
    invoke  CreateThread, 0, 0, ADDR _ProxyFwdThread, ADDR _proxyFwdCtx, 0, 0
    mov     hFwdThread, eax

    ;; Client→target forwarding (this thread)
    invoke  _ProxyForward, pTlsCtx, ADDR targetTls, ADDR _proxyFwdCtx
    mov     _proxyFwdCtx.bDone, 1

    ;; Wait for reverse thread
    invoke  WaitForSingleObject, hFwdThread, 5000
    invoke  CloseHandle, hFwdThread
    invoke  LogMsg, ADDR _szProxyEnd

@phs_close_tls:
    invoke  TlsClose, ADDR targetTls
@phs_close_target:
    invoke  NetClose, targetSock
    xor     eax, eax
    ret

@phs_conn_fail:
    invoke  ProtoSendError, pTlsCtx, ADDR _szProxyFail
    mov     eax, -1
    ret
ProxyHandleServer ENDP

;; =============================================================================
;; _ProxyFwdThread — Thread proc: forward from src→dst (reverse direction)
;; =============================================================================
_ProxyFwdThread PROC lpParam:DWORD
    mov     edx, lpParam
    mov     eax, (PROXY_FWD_CTX PTR [edx]).pSrc
    mov     ecx, (PROXY_FWD_CTX PTR [edx]).pDst
    ;; Forward: src(target) → dst(client)
    invoke  _ProxyForward, eax, ecx, lpParam
    mov     edx, lpParam
    mov     (PROXY_FWD_CTX PTR [edx]).bDone, 1
    ret
_ProxyFwdThread ENDP

;; =============================================================================
;; _ProxyForward — Read from pSrc TLS, write raw to pDst TLS
;; Runs until error or bDone is set
;; =============================================================================
_ProxyForward PROC uses ebx esi edi \
    pSrc:DWORD, pDst:DWORD, pCtx:DWORD

    LOCAL   pBuf:DWORD
    LOCAL   nRecv:DWORD

    invoke  GlobalAlloc, 0, PROXY_FWD_BUF
    test    eax, eax
    jz      @pf_done
    mov     pBuf, eax

@pf_loop:
    mov     edx, pCtx
    cmp     (PROXY_FWD_CTX PTR [edx]).bDone, 1
    je      @pf_free

    ;; Read from source TLS (returns bytes read in eax, 0=error)
    invoke  TlsRecv, pSrc, pBuf, PROXY_FWD_BUF
    test    eax, eax
    jz      @pf_free
    mov     nRecv, eax

    ;; Write to destination TLS
    invoke  TlsSend, pDst, pBuf, nRecv
    test    eax, eax
    jnz     @pf_free
    jmp     @pf_loop

@pf_free:
    invoke  GlobalFree, pBuf
@pf_done:
    ret
_ProxyForward ENDP
