;; =============================================================================
;; client.inc — Client mode: connect, auth, route commands
;; Part of pmash — lightweight remote agent
;; =============================================================================

lstrcmpiA       PROTO :DWORD, :DWORD
wsprintfA       PROTO C :DWORD, :DWORD, :VARARG
lstrcpyA        PROTO :DWORD, :DWORD
ExitProcess     PROTO :DWORD
MoveFileExA     PROTO :DWORD, :DWORD, :DWORD
DeleteFileA     PROTO :DWORD
_AtoI           PROTO :DWORD
_ParseXY        PROTO :DWORD

SSH_PORT        equ 22
CLIENT_TIMEOUT  equ 30000

.data
    _szCmdExec      db "exec", 0
    _szCmdPush      db "push", 0
    _szCmdPull      db "pull", 0
    _szCmdInfo      db "info", 0
    _szCmdPing      db "ping", 0
    _szCmdShot      db "screenshot", 0
    _szCmdUpdate    db "self-update", 0
    _szCmdLs        db "ls", 0
    _szCmdCat       db "cat", 0
    _szCmdShell     db "shell", 0
    _szCmdSync      db "sync", 0
    _szCmdSyncPush  db "sync-push", 0
    _szSyncPushOk   db "sync-push complete", 13, 10, 0
    _szCmdWrite     db "write", 0
    _szCmdPs        db "ps", 0
    _szCmdKill      db "kill", 0
    _szCmdMouse     db "mouse", 0
    _szCmdKey       db "key", 0
    _szCmdWindow    db "window", 0
    _szWriteOk      db "write complete", 13, 10, 0
    _szWriteFail    db "Error: write failed", 13, 10, 0
    _szSyncOk       db "sync complete", 13, 10, 0
    _szSyncFail     db "Error: sync failed", 13, 10, 0
    _szSyncTmp      db ".sync.tmp", 0
    _szFmtDir       db "Get-ChildItem -Name '%s'", 0
    _szFmtDirAll    db "Get-ChildItem -Name", 0
    _szFmtCat       db "Get-Content -Raw '%s'", 0
    _szConnErr      db "Error: connection failed", 13, 10, 0
    _szAuthErr      db "Error: authentication failed", 13, 10, 0
    _szTlsErr       db "Error: TLS handshake failed", 13, 10, 0
    _szInitErr      db "Error: initialization failed", 13, 10, 0
    _szNoArg        db "Error: missing argument", 13, 10, 0
    _szPong         db "pong", 13, 10, 0
    _szPushOk       db "push complete", 13, 10, 0
    _szPullOk       db "pull complete", 13, 10, 0
    _szPushFail     db "Error: push failed", 13, 10, 0
    _szPullFail     db "Error: pull failed", 13, 10, 0
    _szShotFail     db "Error: screenshot failed", 13, 10, 0
    _szDefShot      db "screenshot.bmp", 0
    _szCRLF         db 13, 10, 0

.data?
    _cliTls         TLS_CTX <>
    _cliCmdBuf      BYTE 1024 dup(?)

.code

;; =============================================================================
;; ClientMode — Connect, auth, route command, print result
;; Uses globals: cliArgs, _hStdOut, _hStdErr
;; =============================================================================
ClientMode PROC
    LOCAL   sock:DWORD
    LOCAL   port:WORD
    LOCAL   msg:MRSH_MSG
    LOCAL   pSigs:DWORD
    LOCAL   nSigCount:DWORD
    LOCAL   pSyncPayload:DWORD
    LOCAL   cbSyncPayload:DWORD
    LOCAL   spMd5[16]:BYTE
    LOCAL   lpConnHost:DWORD
    LOCAL   lpTargetHost:DWORD
    LOCAL   rdvResult:RESOLVE_RESULT

    ;; Init winsock
    invoke  NetInit
    test    eax, eax
    jnz     @cm_init_err

    ;; Relay: if -d set, resolve DeviceID via rendezvous first
    cmp     cliArgs.lpDeviceId, 0
    je      @cm_no_rdv
    ;; Need rendezvous server
    cmp     cliArgs.lpRdvServer, 0
    je      @cm_conn_err            ; -d requires -r
    invoke  RelayResolve, cliArgs.lpRdvServer, cliArgs.lpDeviceId, \
            cliArgs.lpRdvKey, ADDR rdvResult
    test    eax, eax
    jnz     @cm_conn_err
    ;; Use resolved address as host
    lea     eax, rdvResult.szAddr
    cmp     byte ptr [eax], 0
    je      @cm_conn_err            ; no address resolved
    mov     cliArgs.lpHost, eax
    ;; Use resolved port if we don't have an explicit one
    cmp     cliArgs.wPort, 0
    jne     @cm_no_rdv
    mov     ax, rdvResult.wPort
    mov     cliArgs.wPort, ax
@cm_no_rdv:

    ;; ProxyJump: if -J set, connect to proxy host instead of target
    mov     eax, cliArgs.lpHost
    mov     lpConnHost, eax         ; default: connect directly to host
    mov     lpTargetHost, 0
    cmp     cliArgs.lpProxy, 0
    je      @cm_no_proxy
    mov     eax, cliArgs.lpProxy
    mov     lpConnHost, eax         ; connect to proxy instead
    mov     eax, cliArgs.lpHost
    mov     lpTargetHost, eax       ; remember real target
@cm_no_proxy:

    ;; Port: explicit or auto-try 8822→9822→22
    movzx   eax, cliArgs.wPort
    test    eax, eax
    jnz     @cm_use_port
    invoke  NetConnect, lpConnHost, DEFAULT_PORT
    cmp     eax, INVALID_SOCKET
    jne     @cm_connected
    invoke  NetConnect, lpConnHost, ALT_PORT
    cmp     eax, INVALID_SOCKET
    jne     @cm_connected
    invoke  NetConnect, lpConnHost, SSH_PORT
    cmp     eax, INVALID_SOCKET
    jne     @cm_connected
    jmp     @cm_conn_err
@cm_use_port:
    mov     port, ax
    invoke  NetConnect, lpConnHost, port
    cmp     eax, INVALID_SOCKET
    je      @cm_conn_err

@cm_connected:
    mov     sock, eax
    invoke  NetSetTimeout, eax, CLIENT_TIMEOUT
    mov     eax, sock
    mov     _cliTls.sock, eax

    ;; TLS or plaintext
    cmp     cliArgs.bPlain, 1
    je      @cm_plain
    invoke  TlsInit, ADDR _cliTls, 0
    test    eax, eax
    jnz     @cm_tls_err
    mov     eax, sock
    mov     _cliTls.sock, eax
    invoke  TlsConnect, ADDR _cliTls, sock, lpConnHost
    test    eax, eax
    jnz     @cm_tls_err
    jmp     @cm_auth
@cm_plain:
    mov     _cliTls.bPlain, 1

@cm_auth:
    invoke  AuthClientHandshake, ADDR _cliTls
    test    eax, eax
    jnz     @cm_auth_err

    ;; ---- ProxyJump: if -J, send PROXY_CONNECT to establish tunnel ----
    cmp     lpTargetHost, 0
    je      @cm_no_tunnel
    ;; Build payload: encode_str(target_host)
    invoke  lstrlenA, lpTargetHost
    mov     ecx, eax
    add     eax, 2
    mov     cbSyncPayload, eax      ; reuse local
    invoke  GlobalAlloc, 0, cbSyncPayload
    test    eax, eax
    jz      @cm_conn_err
    mov     pSyncPayload, eax
    invoke  lstrlenA, lpTargetHost
    invoke  EncodeStr, pSyncPayload, lpTargetHost, eax
    invoke  ProtoSendMsg, ADDR _cliTls, CMD_PROXY_CONNECT, pSyncPayload, cbSyncPayload
    invoke  GlobalFree, pSyncPayload
    ;; Wait for PROXY_OK
    invoke  ProtoRecvMsg, ADDR _cliTls, ADDR msg
    test    eax, eax
    jnz     @cm_conn_err
    cmp     msg.cmdId, CMD_PROXY_OK
    jne     @cm_proxy_fail
    invoke  ProtoFreeMsg, ADDR msg
    ;; Tunnel established — all subsequent commands go through proxy to target
@cm_no_tunnel:

    ;; ---- Command routing ----
    invoke  lstrcmpiA, cliArgs.lpCommand, ADDR _szCmdExec
    test    eax, eax
    jz      @cm_exec
    invoke  lstrcmpiA, cliArgs.lpCommand, ADDR _szCmdPush
    test    eax, eax
    jz      @cm_push
    invoke  lstrcmpiA, cliArgs.lpCommand, ADDR _szCmdPull
    test    eax, eax
    jz      @cm_pull
    invoke  lstrcmpiA, cliArgs.lpCommand, ADDR _szCmdInfo
    test    eax, eax
    jz      @cm_info
    invoke  lstrcmpiA, cliArgs.lpCommand, ADDR _szCmdPing
    test    eax, eax
    jz      @cm_ping
    invoke  lstrcmpiA, cliArgs.lpCommand, ADDR _szCmdShot
    test    eax, eax
    jz      @cm_screenshot
    invoke  lstrcmpiA, cliArgs.lpCommand, ADDR _szCmdUpdate
    test    eax, eax
    jz      @cm_selfupdate
    invoke  lstrcmpiA, cliArgs.lpCommand, ADDR _szCmdLs
    test    eax, eax
    jz      @cm_ls
    invoke  lstrcmpiA, cliArgs.lpCommand, ADDR _szCmdCat
    test    eax, eax
    jz      @cm_cat
    invoke  lstrcmpiA, cliArgs.lpCommand, ADDR _szCmdShell
    test    eax, eax
    jz      @cm_shell
    invoke  lstrcmpiA, cliArgs.lpCommand, ADDR _szCmdSync
    test    eax, eax
    jz      @cm_sync
    invoke  lstrcmpiA, cliArgs.lpCommand, ADDR _szCmdSyncPush
    test    eax, eax
    jz      @cm_sync_push
    invoke  lstrcmpiA, cliArgs.lpCommand, ADDR _szCmdWrite
    test    eax, eax
    jz      @cm_write
    invoke  lstrcmpiA, cliArgs.lpCommand, ADDR _szCmdPs
    test    eax, eax
    jz      @cm_ps
    invoke  lstrcmpiA, cliArgs.lpCommand, ADDR _szCmdKill
    test    eax, eax
    jz      @cm_kill
    invoke  lstrcmpiA, cliArgs.lpCommand, ADDR _szCmdMouse
    test    eax, eax
    jz      @cm_mouse
    invoke  lstrcmpiA, cliArgs.lpCommand, ADDR _szCmdKey
    test    eax, eax
    jz      @cm_key
    invoke  lstrcmpiA, cliArgs.lpCommand, ADDR _szCmdWindow
    test    eax, eax
    jz      @cm_window
    ;; Implicit exec
    invoke  ProtoSendExec, ADDR _cliTls, cliArgs.lpCommand
    jmp     @cm_exec_recv

;; ---- exec ----
@cm_exec:
    cmp     cliArgs.lpArg1, 0
    je      @cm_noarg
    invoke  ProtoSendExec, ADDR _cliTls, cliArgs.lpArg1
@cm_exec_recv:
    invoke  ProtoRecvMsg, ADDR _cliTls, ADDR msg
    test    eax, eax
    jnz     @cm_close
    cmp     msg.cmdId, CMD_ERROR
    je      @cm_exec_err
    cmp     msg.dataLen, 8
    jb      @cm_close0
    ;; Parse binproto EXEC_RESULT: exit_code(4LE) + blob(4BE + data)
    mov     edx, msg.pData
    mov     eax, [edx]
    push    eax                     ; exit code
    add     edx, 4
    mov     eax, [edx]
    bswap   eax                     ; output blob length
    mov     ecx, eax
    add     edx, 4
    cmp     ecx, 0
    je      @cm_exec_noout
    invoke  WriteFile, _hStdOut, edx, ecx, ADDR _dwWritten, 0
@cm_exec_noout:
    pop     eax
    push    eax
    invoke  ProtoFreeMsg, ADDR msg
    invoke  TlsClose, ADDR _cliTls
    invoke  NetClose, sock
    invoke  NetCleanup
    pop     eax
    invoke  ExitProcess, eax
@cm_exec_err:
    cmp     msg.dataLen, 2
    jb      @cm_exec_err_raw
    invoke  DecodeStr, msg.pData
    invoke  WriteFile, _hStdErr, edx, eax, ADDR _dwWritten, 0
    jmp     @cm_exec_err_done
@cm_exec_err_raw:
    invoke  WriteFile, _hStdErr, msg.pData, msg.dataLen, ADDR _dwWritten, 0
@cm_exec_err_done:
    invoke  ProtoFreeMsg, ADDR msg
    jmp     @cm_exit1
@cm_close0:
    invoke  ProtoFreeMsg, ADDR msg
    jmp     @cm_close

;; ---- push ----
@cm_push:
    cmp     cliArgs.lpArg1, 0
    je      @cm_noarg
    cmp     cliArgs.lpArg2, 0
    je      @cm_noarg
    invoke  TransferPush, ADDR _cliTls, cliArgs.lpArg1, cliArgs.lpArg2
    test    eax, eax
    jnz     @cm_push_err
    invoke  ProtoRecvMsg, ADDR _cliTls, ADDR msg
    test    eax, eax
    jnz     @cm_push_err
    invoke  ProtoFreeMsg, ADDR msg
    invoke  StdOut, ADDR _szPushOk
    jmp     @cm_close
@cm_push_err:
    invoke  StdErr, ADDR _szPushFail
    jmp     @cm_exit1

;; ---- pull ----
@cm_pull:
    cmp     cliArgs.lpArg1, 0
    je      @cm_noarg
    cmp     cliArgs.lpArg2, 0
    je      @cm_noarg
    invoke  TransferPull, ADDR _cliTls, cliArgs.lpArg1, cliArgs.lpArg2
    test    eax, eax
    jnz     @cm_pull_err
    invoke  StdOut, ADDR _szPullOk
    jmp     @cm_close
@cm_pull_err:
    invoke  StdErr, ADDR _szPullFail
    jmp     @cm_exit1

;; ---- info ----
@cm_info:
    invoke  ProtoSendMsg, ADDR _cliTls, CMD_INFO_REQ, 0, 0
    jmp     @cm_recv_print

;; ---- ping ----
@cm_ping:
    invoke  ProtoSendPing, ADDR _cliTls
    invoke  ProtoRecvMsg, ADDR _cliTls, ADDR msg
    test    eax, eax
    jnz     @cm_close
    cmp     msg.cmdId, CMD_PONG
    jne     @cm_print_resp
    invoke  StdOut, ADDR _szPong
    invoke  ProtoFreeMsg, ADDR msg
    jmp     @cm_close

;; ---- screenshot ----
@cm_screenshot:
    invoke  ProtoSendMsg, ADDR _cliTls, CMD_SCREENSHOT_REQ, 0, 0
    invoke  ProtoRecvMsg, ADDR _cliTls, ADDR msg
    test    eax, eax
    jnz     @cm_close
    cmp     msg.cmdId, CMD_SCREENSHOT_DATA
    jne     @cm_print_resp
    cmp     cliArgs.lpArg1, 0
    jne     @cm_shot_file
    lea     eax, _szDefShot
    mov     cliArgs.lpArg1, eax
@cm_shot_file:
    invoke  CreateFileA, cliArgs.lpArg1, GENERIC_WRITE, 0, \
            0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0
    cmp     eax, INVALID_HANDLE_VALUE
    je      @cm_shot_fail
    push    eax
    invoke  WriteFile, eax, msg.pData, msg.dataLen, ADDR _dwWritten, 0
    pop     eax
    invoke  CloseHandle, eax
    invoke  StdOut, cliArgs.lpArg1
    invoke  StdOut, ADDR _szCRLF
    invoke  ProtoFreeMsg, ADDR msg
    jmp     @cm_close
@cm_shot_fail:
    invoke  StdErr, ADDR _szShotFail
    invoke  ProtoFreeMsg, ADDR msg
    jmp     @cm_exit1

;; ---- ls ----
@cm_ls:
    cmp     cliArgs.lpArg1, 0
    je      @cm_ls_all
    invoke  wsprintfA, ADDR _cliCmdBuf, ADDR _szFmtDir, cliArgs.lpArg1
    jmp     @cm_ls_send
@cm_ls_all:
    invoke  lstrcpyA, ADDR _cliCmdBuf, ADDR _szFmtDirAll
@cm_ls_send:
    invoke  ProtoSendExec, ADDR _cliTls, ADDR _cliCmdBuf
    jmp     @cm_exec_recv

;; ---- cat ----
@cm_cat:
    cmp     cliArgs.lpArg1, 0
    je      @cm_noarg
    invoke  wsprintfA, ADDR _cliCmdBuf, ADDR _szFmtCat, cliArgs.lpArg1
    invoke  ProtoSendExec, ADDR _cliTls, ADDR _cliCmdBuf
    jmp     @cm_exec_recv

;; ---- self-update ----
@cm_selfupdate:
    cmp     cliArgs.lpArg1, 0
    je      @cm_noarg
    invoke  lstrlenA, cliArgs.lpArg1
    mov     ecx, eax
    invoke  ProtoSendMsg, ADDR _cliTls, CMD_SELF_UPDATE, cliArgs.lpArg1, ecx
    jmp     @cm_recv_print

;; ---- shell ----
@cm_shell:
    ;; Send shell request
    invoke  ProtoSendMsg, ADDR _cliTls, CMD_SHELL_REQ, 0, 0
    ;; Interactive loop: read stdin → send, recv output → print
    ;; For now, just receive output until disconnect (non-interactive)
@cm_shell_loop:
    invoke  ProtoRecvMsg, ADDR _cliTls, ADDR msg
    test    eax, eax
    jnz     @cm_close
    cmp     msg.cmdId, CMD_SHELL_DATA
    jne     @cm_shell_end
    invoke  WriteFile, _hStdOut, msg.pData, msg.dataLen, ADDR _dwWritten, 0
    invoke  ProtoFreeMsg, ADDR msg
    jmp     @cm_shell_loop
@cm_shell_end:
    invoke  ProtoFreeMsg, ADDR msg
    jmp     @cm_close

;; ---- ps (process list) ----
@cm_ps:
    ;; Send NATIVE_PS sub-command
    mov     byte ptr [_cliCmdBuf], NATIVE_PS
    invoke  ProtoSendMsg, ADDR _cliTls, CMD_NATIVE, ADDR _cliCmdBuf, 1
    ;; Receive and print response
    invoke  ProtoRecvMsg, ADDR _cliTls, ADDR msg
    test    eax, eax
    jnz     @cm_close
    cmp     msg.cmdId, CMD_NATIVE_RESP
    jne     @cm_print_resp
    invoke  WriteFile, _hStdOut, msg.pData, msg.dataLen, ADDR _dwWritten, 0
    invoke  StdOut, ADDR _szCRLF
    invoke  ProtoFreeMsg, ADDR msg
    jmp     @cm_close

;; ---- kill (terminate process by PID) ----
@cm_kill:
    ;; Usage: mrsh -h host kill <pid>
    cmp     cliArgs.lpArg1, 0
    je      @cm_noarg
    ;; Parse PID from string (simple atoi)
    invoke  _AtoI, cliArgs.lpArg1
    ;; Build payload: sub_cmd(1) + u32be(pid)
    mov     byte ptr [_cliCmdBuf], NATIVE_KILL
    bswap   eax
    mov     dword ptr [_cliCmdBuf + 1], eax
    invoke  ProtoSendMsg, ADDR _cliTls, CMD_NATIVE, ADDR _cliCmdBuf, 5
    jmp     @cm_recv_print

;; ---- mouse (GUI mouse control) ----
@cm_mouse:
    ;; Usage: mrsh -h host mouse pos|move|click|scroll [args]
    cmp     cliArgs.lpArg1, 0
    je      @cm_noarg
    ;; Dispatch mouse sub-command by first char
    mov     esi, cliArgs.lpArg1
    movzx   eax, byte ptr [esi]
    cmp     al, 'p'                 ; pos
    je      @cm_mouse_pos
    cmp     al, 'P'
    je      @cm_mouse_pos
    cmp     al, 'm'                 ; move
    je      @cm_mouse_move
    cmp     al, 'M'
    je      @cm_mouse_move
    cmp     al, 'c'                 ; click
    je      @cm_mouse_click
    cmp     al, 'C'
    je      @cm_mouse_click
    cmp     al, 's'                 ; scroll
    je      @cm_mouse_scroll
    cmp     al, 'S'
    je      @cm_mouse_scroll
    jmp     @cm_noarg

@cm_mouse_pos:
    mov     byte ptr [_cliCmdBuf], INPUT_MOUSE_POS
    invoke  ProtoSendMsg, ADDR _cliTls, CMD_INPUT, ADDR _cliCmdBuf, 1
    jmp     @cm_input_recv

@cm_mouse_click:
    mov     byte ptr [_cliCmdBuf], INPUT_MOUSE_CLICK
    invoke  ProtoSendMsg, ADDR _cliTls, CMD_INPUT, ADDR _cliCmdBuf, 1
    jmp     @cm_input_recv

@cm_mouse_move:
    ;; Need arg2 = "x,y"
    cmp     cliArgs.lpArg2, 0
    je      @cm_noarg
    mov     byte ptr [_cliCmdBuf], INPUT_MOUSE_MOVE
    ;; Parse "x,y" — find comma
    invoke  _ParseXY, cliArgs.lpArg2
    ;; eax = x, edx = y
    bswap   eax
    mov     dword ptr [_cliCmdBuf + 1], eax
    bswap   edx
    mov     dword ptr [_cliCmdBuf + 5], edx
    invoke  ProtoSendMsg, ADDR _cliTls, CMD_INPUT, ADDR _cliCmdBuf, 9
    jmp     @cm_input_recv

@cm_mouse_scroll:
    cmp     cliArgs.lpArg2, 0
    je      @cm_noarg
    mov     byte ptr [_cliCmdBuf], INPUT_MOUSE_SCROLL
    invoke  _AtoI, cliArgs.lpArg2
    bswap   eax
    mov     dword ptr [_cliCmdBuf + 1], eax
    invoke  ProtoSendMsg, ADDR _cliTls, CMD_INPUT, ADDR _cliCmdBuf, 5
    jmp     @cm_input_recv

@cm_input_recv:
    invoke  ProtoRecvMsg, ADDR _cliTls, ADDR msg
    test    eax, eax
    jnz     @cm_close
    cmp     msg.cmdId, CMD_INPUT_RESP
    jne     @cm_print_resp
    invoke  WriteFile, _hStdOut, msg.pData, msg.dataLen, ADDR _dwWritten, 0
    invoke  StdOut, ADDR _szCRLF
    invoke  ProtoFreeMsg, ADDR msg
    jmp     @cm_close

;; ---- key (GUI keyboard control) ----
@cm_key:
    ;; Usage: mrsh -h host key type "text" | mrsh -h host key tap enter
    cmp     cliArgs.lpArg1, 0
    je      @cm_noarg
    cmp     cliArgs.lpArg2, 0
    je      @cm_noarg
    mov     esi, cliArgs.lpArg1
    movzx   eax, byte ptr [esi]
    cmp     al, 't'                 ; type
    je      @cm_key_type
    cmp     al, 'T'
    je      @cm_key_type
    ;; Default: tap
    jmp     @cm_key_tap

@cm_key_type:
    ;; Build: sub_cmd(1) + text bytes
    mov     byte ptr [_cliCmdBuf], INPUT_KEY_TYPE
    invoke  lstrlenA, cliArgs.lpArg2
    mov     ecx, eax
    invoke  RtlMoveMemory, ADDR _cliCmdBuf + 1, cliArgs.lpArg2, ecx
    inc     ecx                     ; +1 for sub_cmd byte
    invoke  ProtoSendMsg, ADDR _cliTls, CMD_INPUT, ADDR _cliCmdBuf, ecx
    jmp     @cm_input_recv

@cm_key_tap:
    ;; Build: sub_cmd(1) + encode_str(key_name)
    mov     byte ptr [_cliCmdBuf], INPUT_KEY_TAP
    invoke  lstrlenA, cliArgs.lpArg2
    mov     ecx, eax
    lea     edi, _cliCmdBuf + 1
    invoke  EncodeStr, edi, cliArgs.lpArg2, ecx
    add     eax, 1                  ; +1 for sub_cmd byte
    invoke  ProtoSendMsg, ADDR _cliTls, CMD_INPUT, ADDR _cliCmdBuf, eax
    jmp     @cm_input_recv

;; ---- window (GUI window management) ----
@cm_window:
    ;; Usage: mrsh -h host window list|find|activate|close [arg]
    cmp     cliArgs.lpArg1, 0
    je      @cm_noarg
    mov     esi, cliArgs.lpArg1
    movzx   eax, byte ptr [esi]
    cmp     al, 'l'                 ; list
    je      @cm_win_list
    cmp     al, 'L'
    je      @cm_win_list
    cmp     al, 'f'                 ; find
    je      @cm_win_find
    cmp     al, 'F'
    je      @cm_win_find
    cmp     al, 'a'                 ; activate
    je      @cm_win_activate
    cmp     al, 'A'
    je      @cm_win_activate
    cmp     al, 'c'                 ; close
    je      @cm_win_close
    cmp     al, 'C'
    je      @cm_win_close
    jmp     @cm_noarg

@cm_win_list:
    mov     byte ptr [_cliCmdBuf], INPUT_WIN_LIST
    invoke  ProtoSendMsg, ADDR _cliTls, CMD_INPUT, ADDR _cliCmdBuf, 1
    jmp     @cm_input_recv

@cm_win_find:
    cmp     cliArgs.lpArg2, 0
    je      @cm_noarg
    mov     byte ptr [_cliCmdBuf], INPUT_WIN_FIND
    invoke  lstrlenA, cliArgs.lpArg2
    mov     ecx, eax
    lea     edi, _cliCmdBuf + 1
    invoke  EncodeStr, edi, cliArgs.lpArg2, ecx
    add     eax, 1
    invoke  ProtoSendMsg, ADDR _cliTls, CMD_INPUT, ADDR _cliCmdBuf, eax
    jmp     @cm_input_recv

@cm_win_activate:
    cmp     cliArgs.lpArg2, 0
    je      @cm_noarg
    mov     byte ptr [_cliCmdBuf], INPUT_WIN_ACTIVATE
    invoke  _AtoI, cliArgs.lpArg2
    bswap   eax
    mov     dword ptr [_cliCmdBuf + 1], eax
    invoke  ProtoSendMsg, ADDR _cliTls, CMD_INPUT, ADDR _cliCmdBuf, 5
    jmp     @cm_input_recv

@cm_win_close:
    cmp     cliArgs.lpArg2, 0
    je      @cm_noarg
    mov     byte ptr [_cliCmdBuf], INPUT_WIN_CLOSE
    invoke  _AtoI, cliArgs.lpArg2
    bswap   eax
    mov     dword ptr [_cliCmdBuf + 1], eax
    invoke  ProtoSendMsg, ADDR _cliTls, CMD_INPUT, ADDR _cliCmdBuf, 5
    jmp     @cm_input_recv

;; ---- sync-push (delta push to server) ----
@cm_sync_push:
    ;; Usage: mrsh -h host sync-push <local_file> <remote_path>
    cmp     cliArgs.lpArg1, 0
    je      @cm_noarg
    cmp     cliArgs.lpArg2, 0
    je      @cm_noarg

    ;; Step 1: Send CMD_SYNC_PUSH with remote path
    invoke  lstrlenA, cliArgs.lpArg2
    mov     ecx, eax
    add     eax, 2                  ; encode_str overhead
    mov     cbSyncPayload, eax
    invoke  GlobalAlloc, 0, cbSyncPayload
    test    eax, eax
    jz      @cm_sync_fail
    mov     pSyncPayload, eax
    invoke  EncodeStr, pSyncPayload, cliArgs.lpArg2, ecx
    invoke  ProtoSendMsg, ADDR _cliTls, CMD_SYNC_PUSH, pSyncPayload, cbSyncPayload
    invoke  GlobalFree, pSyncPayload
    test    eax, eax
    jnz     @cm_sync_fail

    ;; Step 2: Receive CMD_SYNC_SIGS from server
    invoke  ProtoRecvMsg, ADDR _cliTls, ADDR msg
    test    eax, eax
    jnz     @cm_sync_fail
    cmp     msg.cmdId, CMD_SYNC_SIGS
    jne     @cm_sync_push_err

    ;; Parse server sigs: u32be(count) + sigs[24 bytes each]
    mov     esi, msg.pData
    mov     eax, [esi]
    bswap   eax
    mov     nSigCount, eax
    add     esi, 4
    mov     pSigs, esi              ; points into msg.pData (don't free yet)

    ;; Step 3: Compute delta and send M/D/E stream using CMD_SYNC_DELTA
    ;; Read local file block by block, compare against server sigs
    invoke  CreateFileA, cliArgs.lpArg1, GENERIC_READ, 1, \
            0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0
    cmp     eax, INVALID_HANDLE_VALUE
    je      @cm_sync_push_free
    push    eax                     ; save hFile

    ;; Use _cliCmdBuf as block buffer (1024 bytes, but SYNC_BLOCK_SIZE=4096)
    ;; Need separate allocation for block buffer
    invoke  GlobalAlloc, 0, 4096 + 9  ; block + marker header
    test    eax, eax
    pop     ebx                     ; hFile
    jz      @cm_sync_push_free
    mov     pSyncPayload, eax       ; reuse as block buf
    push    ebx                     ; save hFile again

@cm_sp_loop:
    ;; Read block
    pop     ebx                     ; hFile
    push    ebx
    invoke  ReadFile, ebx, pSyncPayload, 4096, ADDR cbSyncPayload, 0
    test    eax, eax
    jz      @cm_sp_end
    cmp     cbSyncPayload, 0
    je      @cm_sp_end

    ;; Compute Adler32 for this block
    invoke  Adler32, pSyncPayload, cbSyncPayload

    ;; Search server sigs for match (weak hash)
    mov     edi, pSigs
    xor     ecx, ecx
@cm_sp_search:
    cmp     ecx, nSigCount
    jge     @cm_sp_no_match
    cmp     [edi + 4], eax          ; compare adler32
    jne     @cm_sp_next_sig
    ;; Weak match — compute MD5 and compare strong hash
    push    ecx
    push    edi
    invoke  MD5Hash, pSyncPayload, cbSyncPayload, ADDR spMd5
    pop     edi
    pop     ecx
    ;; Compare 16 bytes
    push    ecx
    lea     esi, [edi + 8]
    lea     ebx, spMd5
    mov     ecx, 16
@cm_sp_md5:
    mov     al, [esi]
    cmp     al, [ebx]
    jne     @cm_sp_md5_fail
    inc     esi
    inc     ebx
    dec     ecx
    jnz     @cm_sp_md5
    pop     ecx
    ;; Strong match — send M marker
    mov     byte ptr [_cliCmdBuf], DELTA_MATCH
    mov     eax, [edi]              ; server block index
    bswap   eax
    mov     dword ptr [_cliCmdBuf + 1], eax
    invoke  ProtoSendMsg, ADDR _cliTls, CMD_SYNC_DELTA, ADDR _cliCmdBuf, 5
    jmp     @cm_sp_loop

@cm_sp_md5_fail:
    pop     ecx
@cm_sp_next_sig:
    add     edi, 24
    inc     ecx
    jmp     @cm_sp_search

@cm_sp_no_match:
    ;; Send D marker: [D][len_BE][data]
    ;; Build in temp buffer: shift block data right by 5, prepend header
    mov     eax, cbSyncPayload
    add     eax, 5
    invoke  GlobalAlloc, 0, eax
    test    eax, eax
    jz      @cm_sp_end
    push    eax
    mov     byte ptr [eax], DELTA_DATA
    mov     ecx, cbSyncPayload
    bswap   ecx
    mov     [eax + 1], ecx
    mov     ecx, cbSyncPayload
    lea     edi, [eax + 5]
    invoke  RtlMoveMemory, edi, pSyncPayload, cbSyncPayload
    pop     eax
    push    eax
    mov     ecx, cbSyncPayload
    add     ecx, 5
    invoke  ProtoSendMsg, ADDR _cliTls, CMD_SYNC_DELTA, eax, ecx
    pop     eax
    invoke  GlobalFree, eax
    jmp     @cm_sp_loop

@cm_sp_end:
    ;; Send E marker
    mov     byte ptr [_cliCmdBuf], DELTA_END
    invoke  ProtoSendMsg, ADDR _cliTls, CMD_SYNC_DELTA, ADDR _cliCmdBuf, 1

    pop     ebx                     ; hFile
    invoke  CloseHandle, ebx
    invoke  GlobalFree, pSyncPayload
    invoke  ProtoFreeMsg, ADDR msg  ; free server sigs message

    ;; Wait for CMD_SYNC_DONE
    invoke  ProtoRecvMsg, ADDR _cliTls, ADDR msg
    test    eax, eax
    jnz     @cm_sync_fail
    invoke  ProtoFreeMsg, ADDR msg
    invoke  StdOut, ADDR _szSyncPushOk
    jmp     @cm_close

@cm_sync_push_err:
    invoke  ProtoFreeMsg, ADDR msg
    jmp     @cm_sync_fail
@cm_sync_push_free:
    invoke  ProtoFreeMsg, ADDR msg
    jmp     @cm_sync_fail

;; ---- write (create/overwrite remote file from local) ----
@cm_write:
    ;; Usage: mrsh -h host write <local_file> <remote_path>
    ;; Strategy: read entire file, build payload, send CMD_WRITE
    cmp     cliArgs.lpArg1, 0
    je      @cm_noarg
    cmp     cliArgs.lpArg2, 0
    je      @cm_noarg

    ;; Read local file into temporary buffer
    invoke  CreateFileA, cliArgs.lpArg1, GENERIC_READ, 1, \
            0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0
    cmp     eax, INVALID_HANDLE_VALUE
    je      @cm_write_fail
    mov     pSigs, eax              ; pSigs = hFile (reuse)
    invoke  GetFileSize, pSigs, 0
    mov     nSigCount, eax          ; nSigCount = fileSize (reuse)

    ;; Alloc buffer for file content
    invoke  GlobalAlloc, 0, nSigCount
    test    eax, eax
    jz      @cm_write_close2
    mov     pSyncPayload, eax       ; temp: file content buffer
    invoke  ReadFile, pSigs, pSyncPayload, nSigCount, ADDR cbSyncPayload, 0
    invoke  CloseHandle, pSigs

    ;; Now build CMD_WRITE payload: encode_str(path) + encode_blob(content)
    invoke  lstrlenA, cliArgs.lpArg2
    mov     ebx, eax                ; ebx = pathLen
    mov     eax, nSigCount
    add     eax, ebx
    add     eax, 6                  ; total = 2 + pathLen + 4 + fileSize
    mov     cbSyncPayload, eax      ; reuse as total size
    invoke  GlobalAlloc, 0, cbSyncPayload
    test    eax, eax
    jz      @cm_write_free_content
    push    eax                     ; save pPayload
    invoke  EncodeStr, eax, cliArgs.lpArg2, ebx
    ;; eax = bytes written by EncodeStr
    pop     edi                     ; edi = pPayload
    push    edi
    add     edi, eax
    ;; encode_blob header
    mov     eax, nSigCount
    bswap   eax
    mov     [edi], eax
    add     edi, 4
    ;; Copy file content
    invoke  RtlMoveMemory, edi, pSyncPayload, nSigCount
    ;; Free file content buffer
    invoke  GlobalFree, pSyncPayload
    ;; Send
    pop     pSyncPayload            ; pSyncPayload = pPayload
    invoke  ProtoSendMsg, ADDR _cliTls, CMD_WRITE, pSyncPayload, cbSyncPayload
    push    eax
    invoke  GlobalFree, pSyncPayload
    pop     eax
    test    eax, eax
    jnz     @cm_write_fail

    ;; Receive CMD_WRITE_OK
    invoke  ProtoRecvMsg, ADDR _cliTls, ADDR msg
    test    eax, eax
    jnz     @cm_write_fail
    cmp     msg.cmdId, CMD_WRITE_OK
    jne     @cm_write_err_msg
    invoke  ProtoFreeMsg, ADDR msg
    invoke  StdOut, ADDR _szWriteOk
    jmp     @cm_close

@cm_write_err_msg:
    ;; Print error from server
    cmp     msg.cmdId, CMD_ERROR
    jne     @cm_write_free
    cmp     msg.dataLen, 2
    jb      @cm_write_free
    invoke  DecodeStr, msg.pData
    invoke  WriteFile, _hStdErr, edx, eax, ADDR _dwWritten, 0
@cm_write_free:
    invoke  ProtoFreeMsg, ADDR msg
    jmp     @cm_exit1
@cm_write_free_content:
    invoke  GlobalFree, pSyncPayload
@cm_write_close2:
    invoke  CloseHandle, pSigs
@cm_write_fail:
    invoke  StdErr, ADDR _szWriteFail
    jmp     @cm_exit1

;; ---- sync (delta pull) ----
@cm_sync:
    ;; Usage: mrsh -h host sync <remote_path> <local_path>
    ;; Pulls remote file using delta — only transfers changed blocks
    cmp     cliArgs.lpArg1, 0
    je      @cm_noarg
    cmp     cliArgs.lpArg2, 0
    je      @cm_noarg

    ;; Step 1: Compute local file signatures (if file exists)
    invoke  SyncComputeSignatures, cliArgs.lpArg2, ADDR pSigs, ADDR nSigCount
    ;; If local file doesn't exist, nSigCount = 0 (full download)

    ;; Step 2: Build CMD_SYNC_REQ payload:
    ;;   encode_str(remote_path) + u32be(sig_count) + sigs[24 bytes each]
    invoke  lstrlenA, cliArgs.lpArg1
    push    eax                     ; save path len
    ;; Total: 2 + pathLen + 4 + (nSigCount * 24)
    mov     ecx, nSigCount
    imul    ecx, 24
    add     ecx, 6                  ; 2 (str len) + 4 (sig count)
    add     ecx, eax                ; + pathLen
    mov     cbSyncPayload, ecx
    invoke  GlobalAlloc, 0, ecx
    test    eax, eax
    pop     ecx                     ; restore path len
    jz      @cm_sync_fail
    mov     pSyncPayload, eax

    ;; Write encode_str(remote_path)
    invoke  EncodeStr, pSyncPayload, cliArgs.lpArg1, ecx
    ;; eax = bytes written (2 + pathLen)

    ;; Write u32be(sig_count)
    mov     edi, pSyncPayload
    add     edi, eax
    mov     ecx, nSigCount
    bswap   ecx
    mov     [edi], ecx
    add     edi, 4

    ;; Copy signature array (24 bytes per entry)
    cmp     nSigCount, 0
    je      @cm_sync_send
    mov     eax, nSigCount
    imul    eax, 24
    invoke  RtlMoveMemory, edi, pSigs, eax

@cm_sync_send:
    ;; Free sig buffer if allocated
    cmp     pSigs, 0
    je      @cm_sync_send2
    invoke  GlobalFree, pSigs
@cm_sync_send2:
    invoke  ProtoSendMsg, ADDR _cliTls, CMD_SYNC_REQ, pSyncPayload, cbSyncPayload
    invoke  GlobalFree, pSyncPayload
    test    eax, eax
    jnz     @cm_sync_fail

    ;; Step 3: Receive delta stream and reconstruct file
    ;; Build temp path: localPath + ".sync.tmp"
    invoke  lstrlenA, cliArgs.lpArg2
    add     eax, 11                 ; ".sync.tmp\0"
    invoke  GlobalAlloc, 0, eax
    test    eax, eax
    jz      @cm_sync_fail
    mov     pSyncPayload, eax       ; reuse as pTmpPath
    invoke  lstrcpyA, pSyncPayload, cliArgs.lpArg2
    invoke  lstrlenA, pSyncPayload
    mov     edi, pSyncPayload
    add     edi, eax
    invoke  RtlMoveMemory, edi, ADDR _szSyncTmp, 10

    ;; Recompute local sigs for apply (need original file blocks)
    invoke  SyncComputeSignatures, cliArgs.lpArg2, ADDR pSigs, ADDR nSigCount

    invoke  SyncApplyDelta, ADDR _cliTls, cliArgs.lpArg2, pSyncPayload, \
            pSigs, nSigCount
    mov     ebx, eax                ; save result

    ;; Free sigs
    cmp     pSigs, 0
    je      @cm_sync_rename
    invoke  GlobalFree, pSigs

@cm_sync_rename:
    test    ebx, ebx
    jnz     @cm_sync_cleanup

    ;; Rename temp → target (MoveFileExA with REPLACE_EXISTING)
    invoke  MoveFileExA, pSyncPayload, cliArgs.lpArg2, 1
    invoke  GlobalFree, pSyncPayload
    invoke  StdOut, ADDR _szSyncOk
    jmp     @cm_close

@cm_sync_cleanup:
    ;; Delete temp file on failure
    invoke  DeleteFileA, pSyncPayload
    invoke  GlobalFree, pSyncPayload
@cm_sync_fail:
    invoke  StdErr, ADDR _szSyncFail
    jmp     @cm_exit1

;; ---- Generic recv + print ----
@cm_recv_print:
    invoke  ProtoRecvMsg, ADDR _cliTls, ADDR msg
    test    eax, eax
    jnz     @cm_close
@cm_print_resp:
    cmp     msg.dataLen, 0
    je      @cm_free
    invoke  WriteFile, _hStdOut, msg.pData, msg.dataLen, ADDR _dwWritten, 0
    invoke  StdOut, ADDR _szCRLF
    cmp     msg.cmdId, CMD_ERROR
    jne     @cm_free
    invoke  ProtoFreeMsg, ADDR msg
    jmp     @cm_exit1
@cm_free:
    invoke  ProtoFreeMsg, ADDR msg

@cm_close:
    invoke  TlsClose, ADDR _cliTls
    invoke  NetClose, sock
    invoke  NetCleanup
    invoke  ExitProcess, 0

@cm_noarg:
    invoke  StdErr, ADDR _szNoArg
    jmp     @cm_exit1
@cm_auth_err:
    invoke  StdErr, ADDR _szAuthErr
    invoke  TlsClose, ADDR _cliTls
    invoke  NetClose, sock
    jmp     @cm_exit_net
@cm_tls_err:
    invoke  StdErr, ADDR _szTlsErr
    invoke  NetClose, sock
    jmp     @cm_exit_net
@cm_proxy_fail:
    invoke  ProtoFreeMsg, ADDR msg
@cm_conn_err:
    invoke  StdErr, ADDR _szConnErr
    jmp     @cm_exit_net
@cm_init_err:
    invoke  StdErr, ADDR _szInitErr
@cm_exit_net:
    invoke  NetCleanup
    invoke  ExitProcess, 1
@cm_exit1:
    invoke  TlsClose, ADDR _cliTls
    invoke  NetClose, sock
    invoke  NetCleanup
    invoke  ExitProcess, 1
ClientMode ENDP

;; =============================================================================
;; _AtoI — Simple ASCII-to-integer (decimal, supports negative)
;; =============================================================================
_AtoI PROC lpStr:DWORD
    mov     edx, lpStr
    xor     eax, eax
    xor     ecx, ecx                ; sign flag
    cmp     byte ptr [edx], '-'
    jne     @ai_loop
    mov     ecx, 1
    inc     edx
@ai_loop:
    movzx   ebx, byte ptr [edx]
    cmp     bl, '0'
    jb      @ai_done
    cmp     bl, '9'
    ja      @ai_done
    imul    eax, 10
    sub     bl, '0'
    add     eax, ebx
    inc     edx
    jmp     @ai_loop
@ai_done:
    test    ecx, ecx
    jz      @ai_ret
    neg     eax
@ai_ret:
    ret
_AtoI ENDP

;; =============================================================================
;; _ParseXY — Parse "x,y" string into eax=x, edx=y
;; =============================================================================
_ParseXY PROC lpStr:DWORD
    LOCAL   xVal:DWORD
    ;; Parse X part (up to comma)
    mov     esi, lpStr
    xor     eax, eax
@pxy_x:
    movzx   ecx, byte ptr [esi]
    cmp     cl, ','
    je      @pxy_comma
    cmp     cl, 0
    je      @pxy_done
    imul    eax, 10
    sub     cl, '0'
    movzx   ecx, cl
    add     eax, ecx
    inc     esi
    jmp     @pxy_x
@pxy_comma:
    mov     xVal, eax
    inc     esi                     ; skip comma
    ;; Parse Y part
    xor     eax, eax
@pxy_y:
    movzx   ecx, byte ptr [esi]
    cmp     cl, 0
    je      @pxy_done
    imul    eax, 10
    sub     cl, '0'
    movzx   ecx, cl
    add     eax, ecx
    inc     esi
    jmp     @pxy_y
@pxy_done:
    mov     edx, eax                ; y in edx
    mov     eax, xVal               ; x in eax
    ret
_ParseXY ENDP
