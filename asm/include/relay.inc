;; =============================================================================
;; relay.inc — Rendezvous DeviceID resolution via hbbs UDP
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; Flow: RegisterPeer → PunchHoleRequest → parse PunchHoleResponse
;; Returns: IP:port of target (P2P) or relay server address
;; =============================================================================

;; Winsock2 UDP API
IFNDEF SOCK_DGRAM
SOCK_DGRAM      equ 2
ENDIF
IFNDEF AF_INET
AF_INET         equ 2
ENDIF
IFNDEF IPPROTO_UDP
IPPROTO_UDP     equ 17
ENDIF

socket          PROTO :DWORD, :DWORD, :DWORD
sendto          PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
recvfrom        PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
bind            PROTO :DWORD, :DWORD, :DWORD
htons           PROTO :WORD
ntohs           PROTO :WORD
inet_ntoa       PROTO :DWORD
gethostbyname   PROTO :DWORD
closesocket     PROTO :DWORD
connect         PROTO :DWORD, :DWORD, :DWORD

;; Forward declarations
PbEncodeVarint  PROTO :DWORD, :DWORD
PbWriteString   PROTO :DWORD, :DWORD, :DWORD
PbWriteInt32    PROTO :DWORD, :DWORD, :DWORD
PbWriteSubmsg   PROTO :DWORD, :DWORD, :DWORD, :DWORD
PbDecodeVarint  PROTO :DWORD, :DWORD
PbSkipField     PROTO :DWORD, :DWORD
wsprintfA       PROTO C :DWORD, :DWORD, :VARARG

IFNDEF _GLOBALALLOC_DEFINED
_GLOBALALLOC_DEFINED equ 1
GlobalAlloc     PROTO :DWORD, :DWORD
GlobalFree      PROTO :DWORD
ENDIF
IFNDEF _RTLZEROMEMORY_DEFINED
_RTLZEROMEMORY_DEFINED equ 1
RtlZeroMemory   PROTO :DWORD, :DWORD
ENDIF
IFNDEF _RTLCOPYMEMORY_DEFINED
_RTLCOPYMEMORY_DEFINED equ 1
RtlMoveMemory   PROTO :DWORD, :DWORD, :DWORD
ENDIF

lstrlenA        PROTO :DWORD
lstrcpyA        PROTO :DWORD, :DWORD
_AtoI           PROTO :DWORD
LogMsg          PROTO :DWORD
setsockopt      PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
send            PROTO :DWORD, :DWORD, :DWORD, :DWORD
recv            PROTO :DWORD, :DWORD, :DWORD, :DWORD

;; Forward declarations
_BuildRegisterPeer      PROTO :DWORD
_BuildPunchHoleRequest  PROTO :DWORD, :DWORD, :DWORD
_ParseRdvResponse       PROTO :DWORD, :DWORD, :DWORD
_ParsePunchHoleResponse PROTO :DWORD, :DWORD, :DWORD
_ParseFetchLocalAddr    PROTO :DWORD, :DWORD, :DWORD

;; SOCKADDR_IN structure (16 bytes)
IFNDEF SOCKADDR_IN
SOCKADDR_IN STRUCT
    sin_family  WORD  ?
    sin_port    WORD  ?
    sin_addr    DWORD ?
    sin_zero    BYTE 8 dup(?)
SOCKADDR_IN ENDS
ENDIF

;; RendezvousMessage envelope field numbers (from rdv.proto)
RDV_REGISTER_PEER           equ 6
RDV_REGISTER_PEER_RESPONSE  equ 7
RDV_PUNCH_HOLE_REQUEST      equ 8
RDV_PUNCH_HOLE_RESPONSE     equ 11
RDV_FETCH_LOCAL_ADDR        equ 12
RDV_REQUEST_RELAY           equ 18
RDV_RELAY_RESPONSE          equ 19

;; Rendezvous default port
RDV_PORT        equ 21116

;; Resolve result
RESOLVE_RESULT STRUCT
    szAddr      BYTE 64 dup(?)      ; P2P address "ip:port" or empty
    szRelay     BYTE 128 dup(?)     ; relay server address or empty
    szUuid      BYTE 64 dup(?)      ; relay pairing UUID or empty
    wPort       WORD ?              ; resolved port
    _pad        WORD ?
RESOLVE_RESULT ENDS

.data
    _szRdvResolving db "[rdv] resolving DeviceID: ", 0
    _szRdvResolved  db "[rdv] resolved: ", 0
    _szRdvRelay     db "[rdv] relay: ", 0
    _szRdvFail      db "[rdv] resolve failed", 13, 10, 0
    _szRdvTimeout   db "[rdv] timeout", 13, 10, 0
    _szRdvVersion   db "1.2.7", 0
    _szRdvId        db "pmash-client", 0
    _szFmtAddr      db "%d.%d.%d.%d:%d", 0

.data?
    _rdvBuf         BYTE 4096 dup(?)    ; send/recv buffer
    _rdvSubmsg      BYTE 1024 dup(?)    ; submessage build buffer

.code

;; =============================================================================
;; RelayResolve — Resolve DeviceID via hbbs rendezvous server
;; Args: lpServer (hostname:port), lpDeviceId, lpLicenceKey, pResult (RESOLVE_RESULT)
;; Returns: 0 = success, -1 = failed
;; =============================================================================
RelayResolve PROC uses ebx esi edi \
    lpServer:DWORD, lpDeviceId:DWORD, lpLicenceKey:DWORD, pResult:DWORD

    LOCAL   udpSock:DWORD
    LOCAL   sa:SOCKADDR_IN
    LOCAL   cbSent:DWORD
    LOCAL   cbRecv:DWORD
    LOCAL   cbMsg:DWORD
    LOCAL   nRetries:DWORD
    LOCAL   tv:DWORD

    invoke  RtlZeroMemory, pResult, SIZEOF RESOLVE_RESULT

    ;; Create UDP socket
    invoke  socket, AF_INET, SOCK_DGRAM, IPPROTO_UDP
    cmp     eax, INVALID_SOCKET
    je      @rr_fail
    mov     udpSock, eax

    ;; Resolve server hostname
    ;; Parse "host:port" — find colon
    mov     esi, lpServer
    xor     ecx, ecx
@rr_find_colon:
    mov     al, [esi + ecx]
    cmp     al, 0
    je      @rr_default_port
    cmp     al, ':'
    je      @rr_has_port
    inc     ecx
    jmp     @rr_find_colon

@rr_has_port:
    ;; Null-terminate host at colon, parse port after
    mov     byte ptr [esi + ecx], 0
    lea     eax, [esi + ecx + 1]
    invoke  _AtoI, eax
    push    ax                      ; save port
    invoke  gethostbyname, lpServer
    pop     cx                      ; restore port
    ;; Restore colon
    mov     edx, lpServer
    add     edx, ecx
    ;;mov     byte ptr [edx], ':' ; don't restore, we don't need it
    jmp     @rr_check_host

@rr_default_port:
    mov     cx, RDV_PORT
    invoke  gethostbyname, lpServer

@rr_check_host:
    test    eax, eax
    jz      @rr_close
    ;; hostent->h_addr_list[0]
    mov     edx, [eax + 12]        ; h_addr_list
    mov     edx, [edx]             ; h_addr_list[0]
    mov     eax, [edx]             ; IP address (network order)

    ;; Build sockaddr_in
    mov     sa.sin_family, AF_INET
    push    eax                    ; save IP
    invoke  htons, cx
    mov     sa.sin_port, ax
    pop     eax
    mov     sa.sin_addr, eax

    ;; Connect UDP socket (so we can use send/recv)
    invoke  connect, udpSock, ADDR sa, 16
    test    eax, eax
    jnz     @rr_close

    ;; ---- Step 1: RegisterPeer ----
    invoke  _BuildRegisterPeer, ADDR _rdvSubmsg
    mov     ecx, eax                ; submsg size
    ;; Wrap in RendezvousMessage envelope (field 6)
    invoke  PbWriteSubmsg, ADDR _rdvBuf, RDV_REGISTER_PEER, ADDR _rdvSubmsg, ecx
    mov     cbMsg, eax
    invoke  send, udpSock, ADDR _rdvBuf, cbMsg, 0

    ;; Wait for RegisterPeerResponse (5s timeout via SO_RCVTIMEO)
    mov     tv, 5000                ; 5 second timeout
    invoke  setsockopt, udpSock, 0FFFFh, 1006h, ADDR tv, 4  ; SOL_SOCKET=0xFFFF, SO_RCVTIMEO=0x1006

    invoke  recv, udpSock, ADDR _rdvBuf, 4096, 0
    ;; Ignore response content — just need to register

    ;; ---- Step 2: PunchHoleRequest ----
    invoke  _BuildPunchHoleRequest, ADDR _rdvSubmsg, lpDeviceId, lpLicenceKey
    mov     ecx, eax
    invoke  RtlZeroMemory, ADDR _rdvBuf, 4096
    invoke  PbWriteSubmsg, ADDR _rdvBuf, RDV_PUNCH_HOLE_REQUEST, ADDR _rdvSubmsg, ecx
    mov     cbMsg, eax

    ;; Retry loop: send every 3s, 15s deadline (5 retries)
    mov     nRetries, 0
@rr_punch_loop:
    cmp     nRetries, 5
    jge     @rr_timeout

    invoke  send, udpSock, ADDR _rdvBuf, cbMsg, 0
    inc     nRetries

    ;; Wait for response (3s timeout)
    mov     tv, 3000
    invoke  setsockopt, udpSock, 0FFFFh, 1006h, ADDR tv, 4
    invoke  recv, udpSock, ADDR _rdvBuf, 4096, 0
    cmp     eax, SOCKET_ERROR
    je      @rr_punch_loop
    cmp     eax, 0
    jle     @rr_punch_loop
    mov     cbRecv, eax

    ;; Parse response — find the message type
    invoke  _ParseRdvResponse, ADDR _rdvBuf, cbRecv, pResult
    test    eax, eax
    jz      @rr_ok
    ;; Unrecognized response — retry
    jmp     @rr_punch_loop

@rr_ok:
    invoke  closesocket, udpSock
    xor     eax, eax
    ret

@rr_timeout:
    invoke  LogMsg, ADDR _szRdvTimeout
@rr_close:
    invoke  closesocket, udpSock
@rr_fail:
    mov     eax, -1
    ret
RelayResolve ENDP

;; =============================================================================
;; _BuildRegisterPeer — Build RegisterPeer submessage
;; Returns: size in eax
;; =============================================================================
_BuildRegisterPeer PROC pBuf:DWORD
    LOCAL   off:DWORD
    LOCAL   szPlatform[16]:BYTE
    mov     off, 0
    mov     edi, pBuf

    ;; field 1: id (string)
    invoke  PbWriteString, edi, 1, ADDR _szRdvId
    add     off, eax
    add     edi, eax

    ;; field 5: platform = "windows"
    mov     dword ptr [szPlatform], 'dniw'
    mov     dword ptr [szPlatform + 4], 'swo'
    mov     byte ptr [szPlatform + 7], 0
    invoke  PbWriteString, edi, 5, ADDR szPlatform
    add     off, eax

    mov     eax, off
    ret
_BuildRegisterPeer ENDP

;; =============================================================================
;; _BuildPunchHoleRequest — Build PunchHoleRequest submessage
;; Returns: size in eax
;; =============================================================================
_BuildPunchHoleRequest PROC uses edi pBuf:DWORD, lpDeviceId:DWORD, lpLicenceKey:DWORD
    LOCAL   off:DWORD
    mov     off, 0
    mov     edi, pBuf

    ;; field 1: id (target device ID)
    invoke  PbWriteString, edi, 1, lpDeviceId
    add     off, eax
    add     edi, eax

    ;; field 2: nat_type = ASYMMETRIC (1)
    invoke  PbWriteInt32, edi, 2, 1
    add     off, eax
    add     edi, eax

    ;; field 3: licence_key
    invoke  PbWriteString, edi, 3, lpLicenceKey
    add     off, eax
    add     edi, eax

    ;; field 6: version
    invoke  PbWriteString, edi, 6, ADDR _szRdvVersion
    add     off, eax

    mov     eax, off
    ret
_BuildPunchHoleRequest ENDP

;; =============================================================================
;; _ParseRdvResponse — Parse RendezvousMessage, extract resolve result
;; Returns: 0 = got answer, -1 = not a useful response
;; =============================================================================
_ParseRdvResponse PROC uses esi edi ebx \
    pBuf:DWORD, cbBuf:DWORD, pResult:DWORD

    LOCAL   pCur:DWORD
    LOCAL   pEnd:DWORD
    LOCAL   tag:DWORD
    LOCAL   fieldNum:DWORD
    LOCAL   wireType:DWORD
    LOCAL   fieldLen:DWORD

    mov     eax, pBuf
    mov     pCur, eax
    add     eax, cbBuf
    mov     pEnd, eax

@prr_loop:
    mov     eax, pCur
    cmp     eax, pEnd
    jge     @prr_notfound

    ;; Decode tag
    invoke  PbDecodeVarint, ADDR pCur, ADDR tag
    mov     eax, tag
    mov     ecx, eax
    shr     eax, 3                  ; field number
    mov     fieldNum, eax
    and     ecx, 7                  ; wire type
    mov     wireType, ecx

    ;; We're looking for field 11 (PunchHoleResponse) or 12 (FetchLocalAddr)
    cmp     fieldNum, RDV_PUNCH_HOLE_RESPONSE
    je      @prr_punch_resp
    cmp     fieldNum, RDV_FETCH_LOCAL_ADDR
    je      @prr_fetch_local

    ;; Skip unknown field
    invoke  PbSkipField, ADDR pCur, wireType
    test    eax, eax
    jnz     @prr_notfound
    jmp     @prr_loop

@prr_punch_resp:
    ;; Length-delimited submessage
    invoke  PbDecodeVarint, ADDR pCur, ADDR fieldLen
    ;; Parse PunchHoleResponse fields: socket_addr(1), relay_server(4)
    invoke  _ParsePunchHoleResponse, pCur, fieldLen, pResult
    ret

@prr_fetch_local:
    ;; Length-delimited submessage
    invoke  PbDecodeVarint, ADDR pCur, ADDR fieldLen
    ;; Parse FetchLocalAddr: socket_addr(1), relay_server(2)
    invoke  _ParseFetchLocalAddr, pCur, fieldLen, pResult
    ret

@prr_notfound:
    mov     eax, -1
    ret
_ParseRdvResponse ENDP

;; =============================================================================
;; _ParsePunchHoleResponse — Extract socket_addr and relay_server
;; =============================================================================
_ParsePunchHoleResponse PROC uses esi edi ebx \
    pBuf:DWORD, cbBuf:DWORD, pResult:DWORD

    LOCAL   pCur:DWORD
    LOCAL   pEnd:DWORD
    LOCAL   tag:DWORD
    LOCAL   fnum:DWORD
    LOCAL   wtype:DWORD
    LOCAL   flen:DWORD

    mov     eax, pBuf
    mov     pCur, eax
    add     eax, cbBuf
    mov     pEnd, eax

@pphr_loop:
    mov     eax, pCur
    cmp     eax, pEnd
    jge     @pphr_done

    invoke  PbDecodeVarint, ADDR pCur, ADDR tag
    mov     eax, tag
    mov     ecx, eax
    shr     eax, 3
    mov     fnum, eax
    and     ecx, 7
    mov     wtype, ecx

    cmp     fnum, 1                 ; socket_addr (bytes)
    je      @pphr_addr
    cmp     fnum, 4                 ; relay_server (string)
    je      @pphr_relay

    invoke  PbSkipField, ADDR pCur, wtype
    jmp     @pphr_loop

@pphr_addr:
    invoke  PbDecodeVarint, ADDR pCur, ADDR flen
    ;; socket_addr is AddrMangle-encoded: 4 bytes IP (XOR'd) + 2 bytes port (XOR'd)
    cmp     flen, 6
    jb      @pphr_skip_addr
    mov     esi, pCur
    ;; Decode AddrMangle: XOR each byte with 0x42 (RustDesk convention)
    movzx   eax, byte ptr [esi]
    xor     al, 42h
    movzx   ebx, byte ptr [esi+1]
    xor     bl, 42h
    movzx   ecx, byte ptr [esi+2]
    xor     cl, 42h
    movzx   edx, byte ptr [esi+3]
    xor     dl, 42h
    ;; Port: bytes 4-5 (big-endian, XOR'd)
    push    eax
    push    ebx
    movzx   eax, byte ptr [esi+4]
    xor     al, 42h
    shl     eax, 8
    movzx   ebx, byte ptr [esi+5]
    xor     bl, 42h
    or      eax, ebx
    mov     edi, pResult
    mov     (RESOLVE_RESULT PTR [edi]).wPort, ax
    pop     ebx
    pop     eax
    ;; Format IP:port string
    push    (RESOLVE_RESULT PTR [edi]).wPort
    push    edx
    push    ecx
    push    ebx
    push    eax
    lea     edi, (RESOLVE_RESULT PTR [edi]).szAddr
    lea     eax, _szFmtAddr
    push    eax
    push    edi
    call    wsprintfA
    add     esp, 28

@pphr_skip_addr:
    mov     eax, pCur
    add     eax, flen
    mov     pCur, eax
    jmp     @pphr_loop

@pphr_relay:
    invoke  PbDecodeVarint, ADDR pCur, ADDR flen
    ;; Copy relay server string
    mov     edi, pResult
    lea     edi, (RESOLVE_RESULT PTR [edi]).szRelay
    mov     esi, pCur
    cmp     flen, 127
    jg      @pphr_skip_relay
    invoke  RtlMoveMemory, edi, esi, flen
    mov     byte ptr [edi + flen], 0    ; null-terminate (flen in local, use different approach)
    ;; Advance past string
@pphr_skip_relay:
    mov     eax, pCur
    add     eax, flen
    mov     pCur, eax
    jmp     @pphr_loop

@pphr_done:
    xor     eax, eax
    ret
_ParsePunchHoleResponse ENDP

;; =============================================================================
;; _ParseFetchLocalAddr — Same-LAN: extract socket_addr + relay_server
;; =============================================================================
_ParseFetchLocalAddr PROC uses esi edi ebx \
    pBuf:DWORD, cbBuf:DWORD, pResult:DWORD

    ;; Reuse PunchHoleResponse parser — fields 1 (addr) and 2 (relay) overlap
    ;; FetchLocalAddr has relay_server at field 2, not 4
    ;; For simplicity, just parse field 1 (socket_addr) the same way
    LOCAL   pCur:DWORD
    LOCAL   pEnd:DWORD
    LOCAL   tag:DWORD
    LOCAL   fnum:DWORD
    LOCAL   wtype:DWORD
    LOCAL   flen:DWORD

    mov     eax, pBuf
    mov     pCur, eax
    add     eax, cbBuf
    mov     pEnd, eax

@pfla_loop:
    mov     eax, pCur
    cmp     eax, pEnd
    jge     @pfla_done

    invoke  PbDecodeVarint, ADDR pCur, ADDR tag
    mov     eax, tag
    mov     ecx, eax
    shr     eax, 3
    mov     fnum, eax
    and     ecx, 7
    mov     wtype, ecx

    cmp     fnum, 1                 ; socket_addr
    jne     @pfla_check_relay
    ;; Same decoding as PunchHoleResponse field 1
    invoke  PbDecodeVarint, ADDR pCur, ADDR flen
    cmp     flen, 6
    jb      @pfla_skip
    mov     esi, pCur
    movzx   eax, byte ptr [esi]
    xor     al, 42h
    movzx   ebx, byte ptr [esi+1]
    xor     bl, 42h
    movzx   ecx, byte ptr [esi+2]
    xor     cl, 42h
    movzx   edx, byte ptr [esi+3]
    xor     dl, 42h
    push    eax
    push    ebx
    movzx   eax, byte ptr [esi+4]
    xor     al, 42h
    shl     eax, 8
    movzx   ebx, byte ptr [esi+5]
    xor     bl, 42h
    or      eax, ebx
    mov     edi, pResult
    mov     (RESOLVE_RESULT PTR [edi]).wPort, ax
    pop     ebx
    pop     eax
    push    (RESOLVE_RESULT PTR [edi]).wPort
    push    edx
    push    ecx
    push    ebx
    push    eax
    lea     edi, (RESOLVE_RESULT PTR [edi]).szAddr
    lea     eax, _szFmtAddr
    push    eax
    push    edi
    call    wsprintfA
    add     esp, 28
@pfla_skip:
    mov     eax, pCur
    add     eax, flen
    mov     pCur, eax
    jmp     @pfla_loop

@pfla_check_relay:
    cmp     fnum, 2                 ; relay_server (field 2 in FetchLocalAddr)
    jne     @pfla_other
    invoke  PbDecodeVarint, ADDR pCur, ADDR flen
    mov     edi, pResult
    lea     edi, (RESOLVE_RESULT PTR [edi]).szRelay
    mov     esi, pCur
    cmp     flen, 127
    jg      @pfla_skip2
    invoke  RtlMoveMemory, edi, esi, flen
    add     edi, flen
    mov     byte ptr [edi], 0
@pfla_skip2:
    mov     eax, pCur
    add     eax, flen
    mov     pCur, eax
    jmp     @pfla_loop

@pfla_other:
    invoke  PbSkipField, ADDR pCur, wtype
    jmp     @pfla_loop

@pfla_done:
    xor     eax, eax
    ret
_ParseFetchLocalAddr ENDP
