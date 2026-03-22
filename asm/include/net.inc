;; =============================================================================
;; net.inc — Winsock2 TCP client/server module
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; Provides: NetInit, NetCleanup, NetConnect, NetListen, NetAccept,
;;           NetSend, NetRecv, NetClose, NetSendAll, NetRecvAll,
;;           NetSendLenPrefixed, NetRecvLenPrefixed
;; Requires: ws2_32.lib, kernel32.lib
;; =============================================================================

;; ---- Common constants (if not already defined) ----
IFNDEF NULL
NULL                equ 0
ENDIF
IFNDEF TRUE
TRUE                equ 1
ENDIF
IFNDEF FALSE
FALSE               equ 0
ENDIF

;; ---- Winsock constants ----
AF_INET             equ 2
SOCK_STREAM          equ 1
IPPROTO_TCP          equ 6
INVALID_SOCKET       equ 0FFFFFFFFh
SOCKET_ERROR         equ -1
INADDR_ANY           equ 0
SD_BOTH              equ 2
SOL_SOCKET           equ 0FFFFh
SO_REUSEADDR         equ 4
SO_RCVTIMEO          equ 1006h
SO_SNDTIMEO          equ 1005h
WINSOCK_VERSION      equ 0202h

;; ---- Winsock structures ----
WSADATA STRUCT
    wVersion       WORD  ?
    wHighVersion   WORD  ?
    szDescription  BYTE  257 dup(?)
    szSystemStatus BYTE  129 dup(?)
    iMaxSockets    WORD  ?
    iMaxUdpDg      WORD  ?
    lpVendorInfo   DWORD ?
WSADATA ENDS

sockaddr_in STRUCT
    sin_family     WORD  ?
    sin_port       WORD  ?
    sin_addr       DWORD ?
    sin_zero       BYTE  8 dup(?)
sockaddr_in ENDS

;; ---- Kernel32 prototypes needed by this module ----
IFNDEF _RTLZEROMEMORY_DEFINED
_RTLZEROMEMORY_DEFINED equ 1
RtlZeroMemory   PROTO :DWORD, :DWORD
ENDIF
IFNDEF _GLOBALALLOC_DEFINED
_GLOBALALLOC_DEFINED equ 1
GlobalAlloc     PROTO :DWORD, :DWORD
GlobalFree      PROTO :DWORD
ENDIF

;; ---- Winsock API prototypes ----
WSAStartup      PROTO :WORD, :DWORD
WSACleanup      PROTO
WSAGetLastError PROTO
socket          PROTO :DWORD, :DWORD, :DWORD
closesocket     PROTO :DWORD
connect         PROTO :DWORD, :DWORD, :DWORD
bind            PROTO :DWORD, :DWORD, :DWORD
listen          PROTO :DWORD, :DWORD
accept          PROTO :DWORD, :DWORD, :DWORD
send            PROTO :DWORD, :DWORD, :DWORD, :DWORD
recv            PROTO :DWORD, :DWORD, :DWORD, :DWORD
shutdown        PROTO :DWORD, :DWORD
inet_addr       PROTO :DWORD
htons           PROTO :WORD
ntohs           PROTO :WORD
gethostbyname   PROTO :DWORD
inet_ntoa       PROTO :DWORD
setsockopt      PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD

;; ---- Module data ----
.data?
    _wsaData    WSADATA <>
    _netInited  DWORD   ?

.code

;; =============================================================================
;; NetInit — Initialize Winsock2
;; Returns: 0 = success, -1 = error
;; =============================================================================
NetInit PROC
    cmp     _netInited, 1
    je      @init_ok
    invoke  WSAStartup, WINSOCK_VERSION, ADDR _wsaData
    test    eax, eax
    jnz     @init_fail
    mov     _netInited, 1
@init_ok:
    xor     eax, eax
    ret
@init_fail:
    mov     eax, -1
    ret
NetInit ENDP

;; =============================================================================
;; NetCleanup — Shutdown Winsock2
;; =============================================================================
NetCleanup PROC
    cmp     _netInited, 1
    jne     @cleanup_done
    invoke  WSACleanup
    mov     _netInited, 0
@cleanup_done:
    ret
NetCleanup ENDP

;; =============================================================================
;; NetConnect — Connect TCP to host:port
;; Args: lpHost (ASCIIZ IP or hostname), wPort (host byte order)
;; Returns: socket handle or INVALID_SOCKET on error
;; =============================================================================
NetConnect PROC lpHost:DWORD, wPort:WORD
    LOCAL   sock:DWORD
    LOCAL   sa:sockaddr_in

    invoke  socket, AF_INET, SOCK_STREAM, IPPROTO_TCP
    cmp     eax, INVALID_SOCKET
    je      @conn_fail
    mov     sock, eax

    invoke  RtlZeroMemory, ADDR sa, SIZEOF sockaddr_in
    mov     sa.sin_family, AF_INET

    movzx   eax, wPort
    invoke  htons, ax
    mov     sa.sin_port, ax

    invoke  inet_addr, lpHost
    cmp     eax, INVALID_SOCKET
    jne     @addr_ok

    invoke  gethostbyname, lpHost
    test    eax, eax
    jz      @conn_close
    mov     eax, [eax + 12]
    mov     eax, [eax]
    mov     eax, [eax]

@addr_ok:
    mov     sa.sin_addr, eax

    invoke  connect, sock, ADDR sa, SIZEOF sockaddr_in
    cmp     eax, SOCKET_ERROR
    je      @conn_close

    mov     eax, sock
    ret

@conn_close:
    invoke  closesocket, sock
@conn_fail:
    mov     eax, INVALID_SOCKET
    ret
NetConnect ENDP

;; =============================================================================
;; NetListen — Bind and listen on port
;; Args: wPort (host byte order), nBacklog
;; Returns: listening socket or INVALID_SOCKET
;; =============================================================================
NetListen PROC wPort:WORD, nBacklog:DWORD
    LOCAL   sock:DWORD
    LOCAL   sa:sockaddr_in
    LOCAL   optval:DWORD

    invoke  socket, AF_INET, SOCK_STREAM, IPPROTO_TCP
    cmp     eax, INVALID_SOCKET
    je      @listen_fail
    mov     sock, eax

    mov     optval, 1
    invoke  setsockopt, sock, SOL_SOCKET, SO_REUSEADDR, ADDR optval, 4

    invoke  RtlZeroMemory, ADDR sa, SIZEOF sockaddr_in
    mov     sa.sin_family, AF_INET
    mov     sa.sin_addr, INADDR_ANY

    movzx   eax, wPort
    invoke  htons, ax
    mov     sa.sin_port, ax

    invoke  bind, sock, ADDR sa, SIZEOF sockaddr_in
    cmp     eax, SOCKET_ERROR
    je      @listen_close

    invoke  listen, sock, nBacklog
    cmp     eax, SOCKET_ERROR
    je      @listen_close

    mov     eax, sock
    ret

@listen_close:
    invoke  closesocket, sock
@listen_fail:
    mov     eax, INVALID_SOCKET
    ret
NetListen ENDP

;; =============================================================================
;; NetAccept — Accept incoming connection
;; =============================================================================
NetAccept PROC listenSock:DWORD
    invoke  accept, listenSock, NULL, NULL
    ret
NetAccept ENDP

;; =============================================================================
;; NetSend — Send buffer (single call)
;; =============================================================================
NetSend PROC sock:DWORD, lpBuf:DWORD, nLen:DWORD
    invoke  send, sock, lpBuf, nLen, 0
    ret
NetSend ENDP

;; =============================================================================
;; NetRecv — Receive into buffer (single call)
;; =============================================================================
NetRecv PROC sock:DWORD, lpBuf:DWORD, nBufSize:DWORD
    invoke  recv, sock, lpBuf, nBufSize, 0
    ret
NetRecv ENDP

;; =============================================================================
;; NetSendAll — Send entire buffer (loops until all sent)
;; Returns: 0 = success, -1 = error
;; =============================================================================
NetSendAll PROC uses ebx esi edi sock:DWORD, lpBuf:DWORD, nLen:DWORD
    xor     esi, esi            ; total sent

@sa_loop:
    cmp     esi, nLen
    jge     @sa_done

    mov     ecx, nLen
    sub     ecx, esi            ; remaining
    mov     edx, lpBuf
    add     edx, esi            ; buf + offset
    invoke  send, sock, edx, ecx, 0

    cmp     eax, SOCKET_ERROR
    je      @sa_err
    cmp     eax, 0
    jle     @sa_err

    add     esi, eax
    jmp     @sa_loop

@sa_done:
    xor     eax, eax
    ret
@sa_err:
    mov     eax, -1
    ret
NetSendAll ENDP

;; =============================================================================
;; NetRecvAll — Receive exact number of bytes
;; Returns: 0 = success, -1 = error/closed
;; =============================================================================
NetRecvAll PROC uses ebx esi edi sock:DWORD, lpBuf:DWORD, nLen:DWORD
    xor     esi, esi            ; total received

@ra_loop:
    cmp     esi, nLen
    jge     @ra_done

    mov     ecx, nLen
    sub     ecx, esi
    mov     edx, lpBuf
    add     edx, esi
    invoke  recv, sock, edx, ecx, 0

    cmp     eax, SOCKET_ERROR
    je      @ra_err
    cmp     eax, 0
    jle     @ra_err

    add     esi, eax
    jmp     @ra_loop

@ra_done:
    xor     eax, eax
    ret
@ra_err:
    mov     eax, -1
    ret
NetRecvAll ENDP

;; =============================================================================
;; NetClose — Graceful close
;; =============================================================================
NetClose PROC sock:DWORD
    cmp     sock, INVALID_SOCKET
    je      @nc_done
    cmp     sock, 0
    je      @nc_done
    invoke  shutdown, sock, SD_BOTH
    invoke  closesocket, sock
@nc_done:
    ret
NetClose ENDP

;; =============================================================================
;; NetSendLenPrefixed — Send 4-byte LE length + data
;; Returns: 0 = success, -1 = error
;; =============================================================================
NetSendLenPrefixed PROC sock:DWORD, lpBuf:DWORD, nLen:DWORD
    LOCAL   hdr:DWORD

    ;; Big-endian length header (Rust mrsh wire compat)
    mov     eax, nLen
    bswap   eax
    mov     hdr, eax
    invoke  NetSendAll, sock, ADDR hdr, 4
    test    eax, eax
    jnz     @slp_err
    invoke  NetSendAll, sock, lpBuf, nLen
    ret
@slp_err:
    mov     eax, -1
    ret
NetSendLenPrefixed ENDP

;; =============================================================================
;; NetRecvLenPrefixed — Receive length-prefixed message
;; Args: sock, lpBufOut (ptr to buffer ptr), lpLenOut (ptr to length)
;; Returns: 0 = success, -1 = error. Caller GlobalFree's the buffer.
;; =============================================================================
NetRecvLenPrefixed PROC sock:DWORD, lpBufOut:DWORD, lpLenOut:DWORD
    LOCAL   msgLen:DWORD
    LOCAL   pBuf:DWORD

    invoke  NetRecvAll, sock, ADDR msgLen, 4
    test    eax, eax
    jnz     @rlp_err

    ;; Convert from big-endian
    mov     eax, msgLen
    bswap   eax
    mov     msgLen, eax

    cmp     msgLen, 50000000    ; max 50MB
    ja      @rlp_err

    invoke  GlobalAlloc, 0, msgLen
    test    eax, eax
    jz      @rlp_err
    mov     pBuf, eax

    invoke  NetRecvAll, sock, pBuf, msgLen
    test    eax, eax
    jnz     @rlp_free

    mov     edx, lpBufOut
    mov     eax, pBuf
    mov     [edx], eax
    mov     edx, lpLenOut
    mov     eax, msgLen
    mov     [edx], eax

    xor     eax, eax
    ret

@rlp_free:
    invoke  GlobalFree, pBuf
@rlp_err:
    mov     eax, -1
    ret
NetRecvLenPrefixed ENDP

;; =============================================================================
;; NetSetTimeout — Set recv/send timeout on socket (milliseconds)
;; Args: sock, dwTimeoutMs
;; Returns: 0 = success
;; =============================================================================
NetSetTimeout PROC sock:DWORD, dwTimeoutMs:DWORD
    LOCAL   tv:DWORD
    mov     eax, dwTimeoutMs
    mov     tv, eax
    invoke  setsockopt, sock, SOL_SOCKET, SO_RCVTIMEO, ADDR tv, 4
    invoke  setsockopt, sock, SOL_SOCKET, SO_SNDTIMEO, ADDR tv, 4
    xor     eax, eax
    ret
NetSetTimeout ENDP
