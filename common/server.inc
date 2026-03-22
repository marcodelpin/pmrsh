;; =============================================================================
;; server.inc — Server loop using vtable + common proto (OS-agnostic)
;; Part of pmash — lightweight remote agent
;; =============================================================================

section .data
    _srv_version db "pmash 0.1.0", 0
    _srv_err     db "unknown command", 0
    _srv_info_p1 db '{"hostname":"', 0
    _srv_info_p2 db '","version":"pmash 0.1.0","os":"', 0
    _srv_info_p3_w db 'Windows"}', 0
    _srv_info_p3_l db 'Linux"}', 0

section .bss
    _srv_hostbuf resb 256
    _srv_infobuf resb 512
    _srv_execbuf resb 65536
    _srv_client  resd 1             ; current client fd

section .text

;; =============================================================================
;; server_run(port) — Main server loop
;; =============================================================================
global server_run
server_run:
    push    ebp
    mov     ebp, esp
    push    ebx
    push    esi
    push    edi

    ;; Create socket
    call    [os_vtable.socket]
    test    eax, eax
    js      .fail
    mov     ebx, eax            ; ebx = listen fd

    ;; Bind
    push    dword [ebp+8]       ; port
    push    ebx
    call    [os_vtable.bind]
    add     esp, 8
    test    eax, eax
    jnz     .close_listen

    ;; Listen
    push    5
    push    ebx
    call    [os_vtable.listen]
    add     esp, 8

.accept_loop:
    push    ebx
    call    [os_vtable.accept]
    add     esp, 4
    test    eax, eax
    js      .accept_loop
    mov     [_srv_client], eax

    ;; Auth handshake (accept-all MVP)
    call    .do_auth
    test    eax, eax
    jnz     .disconnect

    ;; Command dispatch loop
.cmd_loop:
    push    dword [_srv_client]
    call    proto_recv_msg
    add     esp, 4
    test    eax, eax
    jle     .disconnect

    ;; cmdId = first byte of _proto_buf
    movzx   eax, byte [_proto_buf]

    cmp     al, CMD_PING
    je      .do_ping
    cmp     al, CMD_EXEC
    je      .do_exec
    cmp     al, CMD_INFO_REQ
    je      .do_info
    ;; Unknown
    jmp     .do_unknown

.do_ping:
    push    0                   ; payload len
    push    0                   ; payload ptr
    push    byte CMD_PONG
    push    dword [_srv_client]
    call    proto_send_msg
    add     esp, 16
    jmp     .cmd_loop

.do_exec:
    ;; Parse: 2-byte BE string len + command
    movzx   eax, byte [_proto_buf+1]
    shl     eax, 8
    movzx   ecx, byte [_proto_buf+2]
    or      eax, ecx            ; command length
    lea     esi, [_proto_buf+3]
    mov     byte [esi+eax], 0   ; null-terminate

    ;; Execute via vtable
    push    65536               ; outbuf size
    push    _srv_execbuf        ; outbuf
    push    esi                 ; cmd
    call    [os_vtable.exec]
    add     esp, 12
    test    eax, eax
    js      .exec_err

    ;; Build EXEC_RESULT: exit_code(4 LE) + blob(4 BE + data)
    mov     ecx, eax            ; output length
    lea     edi, [_srv_infobuf] ; reuse as build buffer
    mov     dword [edi], 0      ; exit_code = 0
    mov     eax, ecx
    bswap   eax
    mov     [edi+4], eax        ; blob length BE
    ;; Copy output
    push    ecx
    lea     edi, [_srv_infobuf+8]
    mov     esi, _srv_execbuf
    rep movsb
    pop     ecx
    ;; Send
    add     ecx, 8             ; total = 4 + 4 + output_len
    push    ecx
    push    _srv_infobuf
    push    byte CMD_EXEC_RESULT
    push    dword [_srv_client]
    call    proto_send_msg
    add     esp, 16
    jmp     .cmd_loop

.exec_err:
    call    .send_error
    jmp     .cmd_loop

.do_info:
    ;; Get hostname
    push    255
    push    _srv_hostbuf
    call    [os_vtable.hostname]
    add     esp, 8

    ;; Build JSON: {"hostname":"<name>","version":"pmash 0.1.0","os":"Linux/Windows"}
    lea     edi, [_srv_infobuf]
    ;; Part 1: {"hostname":"
    mov     esi, _srv_info_p1
    call    .strcpy_edi
    ;; Hostname
    mov     esi, _srv_hostbuf
    call    .strcpy_edi
    ;; Part 2: ","version":"pmash 0.1.0","os":"
    mov     esi, _srv_info_p2
    call    .strcpy_edi
    ;; OS string
    cmp     dword [_os_type], OS_WINDOWS
    je      .info_win
    mov     esi, _srv_info_p3_l
    jmp     .info_os_done
.info_win:
    mov     esi, _srv_info_p3_w
.info_os_done:
    call    .strcpy_edi

    ;; Calculate length
    lea     eax, [_srv_infobuf]
    sub     edi, eax
    ;; Send
    push    edi                 ; len
    push    _srv_infobuf
    push    byte CMD_INFO_RESP
    push    dword [_srv_client]
    call    proto_send_msg
    add     esp, 16
    jmp     .cmd_loop

.do_unknown:
    call    .send_error
    jmp     .cmd_loop

.disconnect:
    push    dword [_srv_client]
    call    [os_vtable.closesock]
    add     esp, 4
    jmp     .accept_loop

.close_listen:
    push    ebx
    call    [os_vtable.closesock]
    add     esp, 4
.fail:
    pop     edi
    pop     esi
    pop     ebx
    pop     ebp
    ret

;; --- Helper: auth handshake (accept-all) ---
.do_auth:
    ;; Recv AUTH_REQUEST
    push    dword [_srv_client]
    call    proto_recv_msg
    add     esp, 4
    test    eax, eax
    jle     .auth_fail

    ;; Send AUTH_CHALLENGE (32 zero bytes)
    lea     edi, [_srv_infobuf]
    xor     al, al
    mov     ecx, 32
    rep stosb
    push    32
    push    _srv_infobuf
    push    byte CMD_AUTH_CHALLENGE
    push    dword [_srv_client]
    call    proto_send_msg
    add     esp, 16

    ;; Recv AUTH_RESPONSE (ignore content)
    push    dword [_srv_client]
    call    proto_recv_msg
    add     esp, 4
    test    eax, eax
    jle     .auth_fail

    ;; Send AUTH_OK: encode_str("pmash 0.1.0") + caps(0) + banner(0)
    lea     edi, [_srv_infobuf]
    mov     byte [edi], 0       ; str len high
    mov     byte [edi+1], 11    ; str len low
    mov     esi, _srv_version
    lea     edi, [_srv_infobuf+2]
    mov     ecx, 11
    rep movsb
    mov     byte [_srv_infobuf+13], 0   ; caps=0
    mov     byte [_srv_infobuf+14], 0   ; banner=0
    push    15
    push    _srv_infobuf
    push    byte CMD_AUTH_OK
    push    dword [_srv_client]
    call    proto_send_msg
    add     esp, 16
    xor     eax, eax
    ret
.auth_fail:
    mov     eax, -1
    ret

;; --- Helper: send error ---
.send_error:
    ;; encode_str("unknown command")
    lea     edi, [_srv_infobuf]
    mov     byte [edi], 0
    mov     byte [edi+1], 15    ; strlen("unknown command")
    mov     esi, _srv_err
    lea     edi, [_srv_infobuf+2]
    mov     ecx, 15
    rep movsb
    push    17                  ; 2 + 15
    push    _srv_infobuf
    push    byte CMD_ERROR
    push    dword [_srv_client]
    call    proto_send_msg
    add     esp, 16
    ret

;; --- Helper: copy ASCIIZ string esi→edi, advance edi ---
.strcpy_edi:
.sc_loop:
    lodsb
    test    al, al
    jz      .sc_done
    stosb
    jmp     .sc_loop
.sc_done:
    ret
