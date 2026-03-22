;; =============================================================================
;; client.inc — Client mode: connect, auth, send command, print result
;; Part of pmash — lightweight remote agent (OS-agnostic via vtable)
;; =============================================================================

section .data
    _cli_err_conn db "Error: connection failed", 10, 0
    _cli_err_auth db "Error: authentication failed", 10, 0
    _cli_pong     db "pong", 10, 0

section .bss
    _cli_fd       resd 1          ; server connection fd

section .text

;; =============================================================================
;; client_run — Connect to server, auth, execute command
;; Args on stack: (host_ip, port, cmd_name, cmd_arg)
;; host_ip = 32-bit network order IP
;; =============================================================================
global client_run
client_run:
    push    ebx
    push    esi
    push    edi
    push    ebp
    mov     ebp, esp
    ; [ebp+20]=host_ip, [ebp+24]=port, [ebp+28]=cmd_name, [ebp+32]=cmd_arg

    ;; Pre-load auth keys (before socket creation to avoid fd conflicts)
    call    auth_load_or_gen

    ;; Create socket + connect
    call    [os_vtable.socket]
    test    eax, eax
    js      .conn_err
    mov     [_cli_fd], eax

    push    dword [ebp+24]      ; port
    push    dword [ebp+20]      ; ip
    push    dword [_cli_fd]
    call    [os_vtable.connect]
    add     esp, 12
    test    eax, eax
    jnz     .conn_err

    ;; Auth handshake (Ed25519)
    push    dword [_cli_fd]
    call    auth_client_handshake
    add     esp, 4
    test    eax, eax
    jnz     .auth_err

    ;; Dispatch command
    mov     esi, [ebp+28]       ; cmd_name

    ;; Check "ping"
    cmp     dword [esi], 'ping'
    je      .cmd_ping

    ;; Check "exec"
    cmp     dword [esi], 'exec'
    je      .cmd_exec

    ;; Check "info"
    cmp     dword [esi], 'info'
    je      .cmd_info

    ;; Check "ps"
    cmp     word [esi], 'ps'
    je      .cmd_ps

    ;; Default: treat as exec
    jmp     .cmd_exec_implicit

.cmd_ping:
    push    0
    push    0
    push    byte CMD_PING
    push    dword [_cli_fd]
    call    proto_send_msg
    add     esp, 16
    ;; Recv pong
    push    dword [_cli_fd]
    call    proto_recv_msg
    add     esp, 4
    mov     esi, _cli_pong
    call    pm_stdout
    jmp     .done

.cmd_exec:
    mov     esi, [ebp+32]       ; arg = command string
    test    esi, esi
    jz      .done
    jmp     .cmd_exec_send
.cmd_exec_implicit:
    mov     esi, [ebp+28]       ; use cmd_name as command
.cmd_exec_send:
    ;; Build EXEC payload: encode_str(cmd) + env_count(0)
    call    pm_strlen
    mov     ecx, eax            ; cmd length
    lea     edi, [_srv_infobuf]
    xor     eax, eax
    mov     ah, cl              ; big-endian high byte (0 for < 256)
    mov     [edi], ah           ; len high
    mov     [edi+1], cl         ; len low
    add     edi, 2
    push    ecx
    rep movsb                   ; copy command
    pop     ecx
    mov     byte [edi], 0       ; env_count = 0
    add     ecx, 3              ; total = 2 + cmdlen + 1
    push    ecx
    push    _srv_infobuf
    push    byte CMD_EXEC
    push    dword [_cli_fd]
    call    proto_send_msg
    add     esp, 16
    ;; Recv result
    push    dword [_cli_fd]
    call    proto_recv_msg
    add     esp, 4
    test    eax, eax
    jle     .done
    ;; Parse EXEC_RESULT: skip cmdId(1) + exit_code(4) + blob_len(4) = 9 bytes header
    cmp     eax, 9
    jl      .done
    mov     ecx, eax
    sub     ecx, 9
    jle     .done
    ;; Print output
    lea     esi, [_proto_buf+9]
    push    ecx
    push    esi
    push    1                   ; stdout
    call    [os_vtable.write]
    add     esp, 12
    ;; Print newline
    mov     esi, _cli_pong + 4  ; just the \n
    push    1
    push    esi
    push    1
    call    [os_vtable.write]
    add     esp, 12
    jmp     .done

.cmd_info:
    push    0
    push    0
    push    byte CMD_INFO_REQ
    push    dword [_cli_fd]
    call    proto_send_msg
    add     esp, 16
    push    dword [_cli_fd]
    call    proto_recv_msg
    add     esp, 4
    test    eax, eax
    jle     .done
    ;; Print response (skip cmdId)
    dec     eax
    push    eax
    lea     esi, [_proto_buf+1]
    push    esi
    push    1
    call    [os_vtable.write]
    add     esp, 12
    jmp     .done

.cmd_ps:
    ;; Send NATIVE ps
    lea     edi, [_srv_infobuf]
    mov     byte [edi], 0x01    ; NATIVE_PS sub-command
    push    1
    push    _srv_infobuf
    push    byte CMD_NATIVE
    push    dword [_cli_fd]
    call    proto_send_msg
    add     esp, 16
    push    dword [_cli_fd]
    call    proto_recv_msg
    add     esp, 4
    test    eax, eax
    jle     .done
    dec     eax
    push    eax
    lea     esi, [_proto_buf+1]
    push    esi
    push    1
    call    [os_vtable.write]
    add     esp, 12
    jmp     .done

.done:
    push    dword [_cli_fd]
    call    [os_vtable.closesock]
    add     esp, 4
    push    0
    call    [os_vtable.exit]

.conn_err:
    mov     esi, _cli_err_conn
    call    pm_stderr
    push    1
    call    [os_vtable.exit]

.auth_err:
    mov     esi, _cli_err_auth
    call    pm_stderr
    push    1
    call    [os_vtable.exit]
