;; =============================================================================
;; server.inc — Server loop: accept, TLS, auth, dispatch commands
;; Part of pmash — lightweight remote agent
;; =============================================================================

GetComputerNameA PROTO :DWORD, :DWORD
wsprintfA       PROTO C :DWORD, :DWORD, :VARARG
lstrcpyA        PROTO :DWORD, :DWORD
Sleep           PROTO :DWORD

IFNDEF _GLOBALALLOC_DEFINED
_GLOBALALLOC_DEFINED equ 1
GlobalAlloc     PROTO :DWORD, :DWORD
GlobalFree      PROTO :DWORD
ENDIF

DEFAULT_PORT    equ 8822
ALT_PORT        equ 9822
TRAY_PORT       equ 9822
ACCEPT_TIMEOUT  equ 5000

.data
    _szLogConn      db "[conn] client accepted", 13, 10, 0
    _szLogTlsOk     db "[tls]  handshake ok", 13, 10, 0
    _szLogTlsFail   db "[tls]  handshake failed", 13, 10, 0
    _szLogAuthOk    db "[auth] authenticated", 13, 10, 0
    _szLogAuthFail  db "[auth] rejected", 13, 10, 0
    _szLogDisc      db "[conn] client disconnected", 13, 10, 0
    _szExecFail     db "exec failed", 0
    _szUnknownCmd   db "unknown command", 0
    _szInfoFmt      db '{"hostname":"%s","version":"pmash 0.1.0","os":"Windows"}', 0

.data?
    _srvInfoBuf     BYTE 256 dup(?)
    _srvInfoBufLen  DWORD ?
    _srvInfoJson    BYTE 512 dup(?)
    _srvCmdBuf      BYTE 1024 dup(?)

.code

;; =============================================================================
;; ServerLoop — Listen, accept, TLS handshake, auth, dispatch commands
;; Args: wPort (listening port)
;; =============================================================================
ServerLoop PROC wPort:WORD
    LOCAL   listenSock:DWORD
    LOCAL   clientSock:DWORD
    LOCAL   serverCred:TLS_CTX
    LOCAL   clientTls:TLS_CTX
    LOCAL   msg:MRSH_MSG
    LOCAL   pOutput:DWORD
    LOCAL   nOutput:DWORD
    LOCAL   nExitCode:DWORD
    LOCAL   pShotBuf:DWORD
    LOCAL   nShotLen:DWORD
    LOCAL   bUseTls:DWORD

    ;; Init compression workspace
    invoke  CompressInit

    ;; TLS init (skip if --plain)
    mov     bUseTls, 0
    cmp     cliArgs.bPlain, 1
    je      @sl_no_tls
    invoke  TlsInit, ADDR serverCred, 1
    test    eax, eax
    jnz     @sl_no_tls
    mov     bUseTls, 1
@sl_no_tls:

    invoke  NetListen, wPort, 5
    cmp     eax, INVALID_SOCKET
    je      @sl_fail
    mov     listenSock, eax
    invoke  NetSetTimeout, listenSock, ACCEPT_TIMEOUT

@sl_accept:
    cmp     _svcStopFlag, 1
    je      @sl_stop
    invoke  NetAccept, listenSock
    cmp     eax, INVALID_SOCKET
    je      @sl_accept
    mov     clientSock, eax
    invoke  LogMsg, ADDR _szLogConn

    ;; Per-client setup
    invoke  RtlZeroMemory, ADDR clientTls, SIZEOF TLS_CTX
    mov     eax, clientSock
    mov     clientTls.sock, eax

    cmp     bUseTls, 1
    jne     @sl_plain
    ;; TLS handshake
    mov     eax, serverCred.hCred.dwLower
    mov     clientTls.hCred.dwLower, eax
    mov     eax, serverCred.hCred.dwUpper
    mov     clientTls.hCred.dwUpper, eax
    mov     clientTls.bServer, 1
    invoke  GlobalAlloc, 0, TLS_RECV_BUF_SIZE
    test    eax, eax
    jz      @sl_close_raw
    mov     clientTls.recvBuf, eax
    mov     clientTls.recvLen, 0
    mov     clientTls.recvCap, TLS_RECV_BUF_SIZE
    invoke  TlsAccept, ADDR clientTls, clientSock
    test    eax, eax
    jnz     @sl_tls_fail
    invoke  LogMsg, ADDR _szLogTlsOk
    jmp     @sl_auth
@sl_plain:
    mov     clientTls.bPlain, 1

@sl_auth:
    invoke  AuthServerHandshake, ADDR clientTls
    test    eax, eax
    jnz     @sl_auth_fail
    invoke  LogMsg, ADDR _szLogAuthOk

    ;; ---- Command dispatch loop ----
@sl_cmd:
    invoke  ProtoRecvMsg, ADDR clientTls, ADDR msg
    test    eax, eax
    jnz     @sl_disc
    movzx   eax, msg.cmdId

    cmp     al, CMD_PING
    je      @sl_pong
    cmp     al, CMD_EXEC
    je      @sl_exec
    cmp     al, CMD_INFO_REQ
    je      @sl_info
    cmp     al, CMD_PUSH_START
    je      @sl_push
    cmp     al, CMD_PULL_REQ
    je      @sl_pull
    cmp     al, CMD_SELF_UPDATE
    je      @sl_update
    cmp     al, CMD_SCREENSHOT_REQ
    je      @sl_shot
    cmp     al, CMD_SHELL_REQ
    je      @sl_shell
    cmp     al, CMD_SYNC_REQ
    je      @sl_sync
    cmp     al, CMD_SYNC_PUSH
    je      @sl_sync_push
    cmp     al, CMD_WRITE
    je      @sl_write
    cmp     al, CMD_NATIVE
    je      @sl_native
    cmp     al, CMD_INPUT
    je      @sl_input
    cmp     al, CMD_PROXY_CONNECT
    je      @sl_proxy
    ;; Unknown
    invoke  ProtoSendError, ADDR clientTls, ADDR _szUnknownCmd
    invoke  ProtoFreeMsg, ADDR msg
    jmp     @sl_cmd

@sl_pong:
    invoke  ProtoSendPong, ADDR clientTls
    invoke  ProtoFreeMsg, ADDR msg
    jmp     @sl_cmd

@sl_exec:
    invoke  DecodeStr, msg.pData
    mov     byte ptr [edx + eax], 0
    invoke  ExecCommand, edx, ADDR pOutput, ADDR nOutput, ADDR nExitCode
    test    eax, eax
    jnz     @sl_exec_err
    invoke  ProtoSendResult, ADDR clientTls, pOutput, nExitCode
    invoke  GlobalFree, pOutput
    invoke  ProtoFreeMsg, ADDR msg
    jmp     @sl_cmd
@sl_exec_err:
    invoke  ProtoSendError, ADDR clientTls, ADDR _szExecFail
    invoke  ProtoFreeMsg, ADDR msg
    jmp     @sl_cmd

@sl_info:
    mov     _srvInfoBufLen, 256
    invoke  GetComputerNameA, ADDR _srvInfoBuf, ADDR _srvInfoBufLen
    invoke  wsprintfA, ADDR _srvInfoJson, ADDR _szInfoFmt, ADDR _srvInfoBuf
    invoke  lstrlenA, ADDR _srvInfoJson
    mov     ecx, eax
    invoke  ProtoSendMsg, ADDR clientTls, CMD_INFO_RESP, ADDR _srvInfoJson, ecx
    invoke  ProtoFreeMsg, ADDR msg
    jmp     @sl_cmd

@sl_push:
    ;; Parse path from PUSH_START — keep msg alive, free later
    mov     esi, msg.pData
    add     esi, 8
    movzx   eax, byte ptr [esi]
    shl     eax, 8
    movzx   ecx, byte ptr [esi + 1]
    or      eax, ecx
    add     esi, 2
    mov     byte ptr [esi + eax], 0
    ;; Open file using path directly from msg.pData (not copied)
    invoke  CreateFileA, esi, GENERIC_WRITE, 0, \
            0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0
    cmp     eax, INVALID_HANDLE_VALUE
    je      @sl_push_end
    mov     pShotBuf, eax
    invoke  ProtoFreeMsg, ADDR msg      ; free PUSH_START now
@sl_push_recv:
    invoke  ProtoRecvMsg, ADDR clientTls, ADDR msg
    test    eax, eax
    jnz     @sl_push_close
    movzx   ebx, msg.cmdId
    cmp     bl, CMD_PUSH_DATA
    jne     @sl_push_chk
    invoke  WriteFile, pShotBuf, msg.pData, msg.dataLen, ADDR nOutput, 0
    invoke  ProtoFreeMsg, ADDR msg
    jmp     @sl_push_recv
@sl_push_chk:
    invoke  ProtoFreeMsg, ADDR msg
    cmp     bl, CMD_PUSH_END
    je      @sl_push_close
    jmp     @sl_push_recv
@sl_push_close:
    invoke  CloseHandle, pShotBuf
@sl_push_end:
    invoke  ProtoFreeMsg, ADDR msg
    invoke  ProtoSendMsg, ADDR clientTls, CMD_PUSH_OK, 0, 0
    jmp     @sl_cmd

@sl_pull:
    invoke  TransferHandlePull, ADDR clientTls, ADDR msg
    invoke  ProtoFreeMsg, ADDR msg
    jmp     @sl_cmd

@sl_update:
    invoke  SelfUpdate, msg.pData
    test    eax, eax
    jnz     @sl_update_err
    invoke  ProtoSendMsg, ADDR clientTls, CMD_SELF_UPDATE_OK, 0, 0
    invoke  ProtoFreeMsg, ADDR msg
    jmp     @sl_cmd
@sl_update_err:
    invoke  ProtoSendError, ADDR clientTls, ADDR _szExecFail
    invoke  ProtoFreeMsg, ADDR msg
    jmp     @sl_cmd

@sl_shot:
    invoke  ScreenCapture, ADDR pShotBuf, ADDR nShotLen
    test    eax, eax
    jnz     @sl_shot_err
    invoke  ProtoSendMsg, ADDR clientTls, CMD_SCREENSHOT_DATA, pShotBuf, nShotLen
    invoke  GlobalFree, pShotBuf
    invoke  ProtoFreeMsg, ADDR msg
    jmp     @sl_cmd
@sl_shot_err:
    invoke  ProtoSendError, ADDR clientTls, ADDR _szExecFail
    invoke  ProtoFreeMsg, ADDR msg
    jmp     @sl_cmd

@sl_shell:
    invoke  ProtoFreeMsg, ADDR msg
    invoke  ShellHandleServer, ADDR clientTls
    jmp     @sl_cmd

@sl_sync:
    invoke  SyncHandleServer, ADDR clientTls, ADDR msg
    invoke  ProtoFreeMsg, ADDR msg
    jmp     @sl_cmd

@sl_sync_push:
    invoke  SyncHandlePush, ADDR clientTls, ADDR msg
    invoke  ProtoFreeMsg, ADDR msg
    jmp     @sl_cmd

@sl_native:
    invoke  NativeHandleServer, ADDR clientTls, ADDR msg
    invoke  ProtoFreeMsg, ADDR msg
    jmp     @sl_cmd

@sl_input:
    invoke  InputHandleServer, ADDR clientTls, ADDR msg
    invoke  ProtoFreeMsg, ADDR msg
    jmp     @sl_cmd

@sl_proxy:
    ;; Proxy blocks until tunnel closes — then returns to accept loop
    invoke  ProxyHandleServer, ADDR clientTls, ADDR msg
    invoke  ProtoFreeMsg, ADDR msg
    jmp     @sl_disc          ; tunnel done, disconnect client

@sl_write:
    ;; CMD_WRITE payload: encode_str(path) + encode_blob(content)
    mov     esi, msg.pData
    ;; Decode path (2-byte BE len + chars)
    movzx   eax, byte ptr [esi]
    shl     eax, 8
    movzx   ecx, byte ptr [esi + 1]
    or      eax, ecx
    add     esi, 2
    mov     byte ptr [esi + eax], 0     ; null-terminate path
    push    esi                         ; save path ptr
    add     esi, eax                    ; advance past path
    ;; Decode blob (4-byte BE len + data)
    mov     eax, [esi]
    bswap   eax
    mov     ecx, eax                    ; ecx = content length
    add     esi, 4                      ; esi = content data
    ;; Open file for writing
    pop     edx                         ; edx = path ptr
    push    ecx                         ; save content length
    push    esi                         ; save content ptr
    invoke  CreateFileA, edx, GENERIC_WRITE, 0, \
            0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0
    cmp     eax, INVALID_HANDLE_VALUE
    je      @sl_write_err
    mov     pShotBuf, eax               ; reuse as file handle
    pop     esi                         ; content ptr
    pop     ecx                         ; content length
    invoke  WriteFile, pShotBuf, esi, ecx, ADDR nOutput, 0
    invoke  CloseHandle, pShotBuf
    invoke  ProtoSendMsg, ADDR clientTls, CMD_WRITE_OK, 0, 0
    invoke  ProtoFreeMsg, ADDR msg
    jmp     @sl_cmd
@sl_write_err:
    pop     esi
    pop     ecx
    invoke  ProtoSendError, ADDR clientTls, ADDR _szExecFail
    invoke  ProtoFreeMsg, ADDR msg
    jmp     @sl_cmd

    ;; ---- Cleanup paths ----
@sl_disc:
    invoke  LogMsg, ADDR _szLogDisc
    invoke  TlsClose, ADDR clientTls
    invoke  NetClose, clientSock
    jmp     @sl_accept
@sl_auth_fail:
    invoke  LogMsg, ADDR _szLogAuthFail
    invoke  TlsClose, ADDR clientTls
    invoke  NetClose, clientSock
    jmp     @sl_accept
@sl_tls_fail:
    invoke  LogMsg, ADDR _szLogTlsFail
    invoke  GlobalFree, clientTls.recvBuf
    invoke  NetClose, clientSock
    jmp     @sl_accept
@sl_close_raw:
    invoke  NetClose, clientSock
    jmp     @sl_accept
@sl_stop:
    invoke  NetClose, listenSock
@sl_fail:
    ret
ServerLoop ENDP
