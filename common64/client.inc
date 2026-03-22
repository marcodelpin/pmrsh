;; =============================================================================
;; client.inc — Client mode (x86_64)
;; Part of pmash — lightweight remote agent
;; =============================================================================

section .data
    _cli_err_conn db "Error: connection failed", 10, 0
    _cli_err_auth db "Error: authentication failed", 10, 0
    _cli_pong     db "pong", 10, 0

section .bss
    _cli_fd       resd 1

section .text

;; client_run(rdi=host_ip, rsi=port, rdx=cmd_name, rcx=cmd_arg)
global client_run
client_run:
    push    rbx
    push    r12
    push    r13
    push    r14
    mov     r12d, edi              ; host_ip (network order)
    mov     r13d, esi              ; port
    mov     r14, rdx               ; cmd_name
    mov     rbx, rcx               ; cmd_arg

    ;; Pre-load auth keys
    call    auth_load_or_gen

    ;; Create socket + connect
    call    [os_vtable.socket]
    test    eax, eax
    js      .conn_err
    mov     [_cli_fd], eax

    mov     edi, eax
    mov     esi, r12d              ; ip
    mov     edx, r13d              ; port
    call    [os_vtable.connect]
    test    eax, eax
    jnz     .conn_err

    ;; Auth handshake
    mov     edi, [_cli_fd]
    call    auth_client_handshake
    test    eax, eax
    jnz     .auth_err

    ;; Dispatch command
    mov     rsi, r14               ; cmd_name

    ;; Check "ping"
    cmp     dword [rsi], 'ping'
    je      .cmd_ping

    ;; Check "exec"
    cmp     dword [rsi], 'exec'
    je      .cmd_exec

    ;; Check "info"
    cmp     dword [rsi], 'info'
    je      .cmd_info

    ;; Check "ps"
    cmp     word [rsi], 'ps'
    je      .cmd_ps

    ;; Default: treat as exec
    jmp     .cmd_exec_implicit

.cmd_ping:
    mov     edi, [_cli_fd]
    mov     sil, CMD_PING
    xor     edx, edx
    xor     ecx, ecx
    call    proto_send_msg
    ;; Recv pong
    mov     edi, [_cli_fd]
    call    proto_recv_msg
    lea     rdi, [_cli_pong]
    call    pm_stdout
    jmp     .done

.cmd_exec:
    mov     rsi, rbx               ; arg = command string
    test    rsi, rsi
    jz      .done
    jmp     .cmd_exec_send
.cmd_exec_implicit:
    mov     rsi, r14               ; use cmd_name as command
.cmd_exec_send:
    ;; Build EXEC payload: encode_str(cmd) + env_count(0)
    mov     rdi, rsi
    call    pm_strlen
    mov     ecx, eax               ; cmd length
    lea     rdi, [_srv_infobuf]
    xor     eax, eax
    mov     ah, cl                 ; big-endian high byte
    mov     [rdi], ah              ; len high
    mov     [rdi+1], cl            ; len low
    add     rdi, 2
    push    rcx
    rep movsb
    pop     rcx
    mov     byte [rdi], 0          ; env_count = 0
    add     ecx, 3                 ; total = 2 + cmdlen + 1
    mov     edi, [_cli_fd]
    mov     sil, CMD_EXEC
    lea     rdx, [_srv_infobuf]
    call    proto_send_msg
    ;; Recv result
    mov     edi, [_cli_fd]
    call    proto_recv_msg
    test    eax, eax
    jle     .done
    ;; Parse EXEC_RESULT: skip cmdId(1) + exit_code(4) + blob_len(4) = 9 bytes
    cmp     eax, 9
    jl      .done
    mov     ecx, eax
    sub     ecx, 9
    jle     .done
    ;; Print output
    mov     edi, 1                 ; stdout
    lea     rsi, [_proto_buf+9]
    mov     edx, ecx
    call    [os_vtable.write]
    ;; Print newline
    mov     edi, 1
    lea     rsi, [_cli_pong + 4]   ; just the \n
    mov     edx, 1
    call    [os_vtable.write]
    jmp     .done

.cmd_info:
    mov     edi, [_cli_fd]
    mov     sil, CMD_INFO_REQ
    xor     edx, edx
    xor     ecx, ecx
    call    proto_send_msg
    mov     edi, [_cli_fd]
    call    proto_recv_msg
    test    eax, eax
    jle     .done
    ;; Print (skip cmdId)
    dec     eax
    mov     edi, 1
    lea     rsi, [_proto_buf+1]
    mov     edx, eax
    call    [os_vtable.write]
    jmp     .done

.cmd_ps:
    ;; Send NATIVE ps
    lea     rdi, [_srv_infobuf]
    mov     byte [rdi], 0x01       ; NATIVE_PS
    mov     edi, [_cli_fd]
    mov     sil, CMD_NATIVE
    lea     rdx, [_srv_infobuf]
    mov     ecx, 1
    call    proto_send_msg
    mov     edi, [_cli_fd]
    call    proto_recv_msg
    test    eax, eax
    jle     .done
    dec     eax
    mov     edi, 1
    lea     rsi, [_proto_buf+1]
    mov     edx, eax
    call    [os_vtable.write]
    jmp     .done

.done:
    mov     edi, [_cli_fd]
    call    [os_vtable.closesock]
    xor     edi, edi
    call    [os_vtable.exit]

.conn_err:
    lea     rdi, [_cli_err_conn]
    call    pm_stderr
    mov     edi, 1
    call    [os_vtable.exit]

.auth_err:
    lea     rdi, [_cli_err_auth]
    call    pm_stderr
    mov     edi, 1
    call    [os_vtable.exit]
