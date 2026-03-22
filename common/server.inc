;; =============================================================================
;; server.inc — Server loop using vtable + common proto (OS-agnostic)
;; Part of pmash — lightweight remote agent
;; =============================================================================

PUSH_CHUNK equ 32768

section .data
    _srv_version db "pmash 0.1.0", 0
    _srv_err     db "unknown command", 0
    _srv_info_p1 db '{"hostname":"', 0
    _srv_info_p2 db '","version":"pmash 0.1.0","os":"', 0
    _srv_info_p3_w db 'Windows"}', 0
    _srv_info_p3_l db 'Linux"}', 0
    _srv_killed  db "killed", 0
    _srv_killfail db "kill failed", 0
    _srv_psfmt   db '{"pid":%d,"name":"%s"}', 0
    _srv_file_err db "file error", 0
    _dbg_wait db "W", 10, 0
    _dbg_accepted db "A", 10, 0
    _dbg_a1 db "[auth] waiting for AUTH_REQUEST", 10, 0
    _dbg_a2 db "[auth] recv_msg returned", 10, 0
    _dbg_a3 db "[auth] sent CHALLENGE", 10, 0
    _dbg_a4 db "[auth] recv RESPONSE returned", 10, 0
    _dbg_a5 db "[auth] sending AUTH_OK", 10, 0
    _dbg_a6 db "[auth] DONE - authenticated", 10, 0

_srv_ps_cmd db "ps -eo pid,comm --no-headers 2>/dev/null || tasklist /FO CSV /NH 2>nul", 0

section .bss
    _srv_hostbuf resb 256
    _srv_infobuf resb 512
    _srv_execbuf resb 65536
    _srv_filebuf resb 32768
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
    ;; Debug: print "W" (waiting) to stderr before accept
    push    ebx
    push    ecx
    push    edx
    mov     eax, 4
    mov     ebx, 2
    mov     ecx, _dbg_wait
    mov     edx, 2
    int     0x80
    pop     edx
    pop     ecx
    pop     ebx

    push    ebx
    call    [os_vtable.accept]
    add     esp, 4

    ;; Debug: print "A" + fd after accept
    push    eax
    push    ebx
    push    ecx
    push    edx
    mov     ebx, 2
    mov     ecx, _dbg_accepted
    mov     edx, 2
    push    eax
    mov     eax, 4
    int     0x80
    pop     eax
    pop     edx
    pop     ecx
    pop     ebx
    pop     eax

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
    cmp     al, CMD_PUSH_START
    je      .do_push
    cmp     al, CMD_PULL_REQ
    je      .do_pull
    cmp     al, CMD_WRITE
    je      .do_write
    cmp     al, CMD_NATIVE
    je      .do_native
    cmp     al, CMD_SYNC_REQ
    je      .do_sync
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

;; ==== PUSH: receive file from client ====
.do_push:
    ;; PUSH_START payload: file_size(8LE) + encode_str(path)
    lea     esi, [_proto_buf+1]     ; skip cmdId
    add     esi, 8                  ; skip file_size (8 bytes LE)
    ;; Decode path: 2-byte BE len + string
    movzx   eax, byte [esi]
    shl     eax, 8
    movzx   ecx, byte [esi+1]
    or      eax, ecx
    add     esi, 2
    mov     byte [esi+eax], 0       ; null-terminate path
    ;; Open file for writing (flags=1 = WRONLY|CREAT|TRUNC)
    push    1
    push    esi
    call    [os_vtable.open]
    add     esp, 8
    test    eax, eax
    js      .push_err
    mov     edi, eax                ; edi = file fd
    ;; Receive data chunks until PUSH_END
.push_recv:
    push    dword [_srv_client]
    call    proto_recv_msg
    add     esp, 4
    test    eax, eax
    jle     .push_close
    movzx   ecx, byte [_proto_buf]
    cmp     cl, CMD_PUSH_DATA
    jne     .push_chk_end
    ;; Write chunk: proto_buf+1, length = msg_len - 1
    dec     eax                     ; payload len = msg_len - 1
    push    eax
    lea     esi, [_proto_buf+1]
    push    esi
    push    edi
    call    [os_vtable.write]
    add     esp, 12
    jmp     .push_recv
.push_chk_end:
    cmp     cl, CMD_PUSH_END
    je      .push_close
    jmp     .push_recv
.push_close:
    push    edi
    call    [os_vtable.close]
    add     esp, 4
    ;; Send PUSH_OK
    push    0
    push    0
    push    byte CMD_PUSH_OK
    push    dword [_srv_client]
    call    proto_send_msg
    add     esp, 16
    jmp     .cmd_loop
.push_err:
    call    .send_error
    jmp     .cmd_loop

;; ==== PULL: send file to client ====
.do_pull:
    ;; Payload: encode_str(path)
    lea     esi, [_proto_buf+1]
    movzx   eax, byte [esi]
    shl     eax, 8
    movzx   ecx, byte [esi+1]
    or      eax, ecx
    add     esi, 2
    mov     byte [esi+eax], 0
    ;; Open file for reading (flags=0 = RDONLY)
    push    0
    push    esi
    call    [os_vtable.open]
    add     esp, 8
    test    eax, eax
    js      .pull_err
    mov     edi, eax                ; edi = file fd
.pull_loop:
    ;; Read chunk
    push    PUSH_CHUNK
    push    _srv_filebuf
    push    edi
    call    [os_vtable.read]
    add     esp, 12
    test    eax, eax
    jle     .pull_end
    ;; Send PULL_DATA
    push    eax
    push    _srv_filebuf
    push    byte CMD_PULL_DATA
    push    dword [_srv_client]
    call    proto_send_msg
    add     esp, 16
    jmp     .pull_loop
.pull_end:
    push    edi
    call    [os_vtable.close]
    add     esp, 4
    ;; Send PULL_END
    push    0
    push    0
    push    byte CMD_PULL_END
    push    dword [_srv_client]
    call    proto_send_msg
    add     esp, 16
    jmp     .cmd_loop
.pull_err:
    ;; Send error
    lea     edi, [_srv_infobuf]
    mov     byte [edi], 0
    mov     byte [edi+1], 10
    mov     esi, _srv_file_err
    lea     edi, [_srv_infobuf+2]
    mov     ecx, 10
    rep movsb
    push    12
    push    _srv_infobuf
    push    byte CMD_ERROR
    push    dword [_srv_client]
    call    proto_send_msg
    add     esp, 16
    jmp     .cmd_loop

;; ==== WRITE: create/overwrite file ====
.do_write:
    ;; Payload: encode_str(path) + encode_blob(content)
    lea     esi, [_proto_buf+1]
    ;; Decode path
    movzx   eax, byte [esi]
    shl     eax, 8
    movzx   ecx, byte [esi+1]
    or      eax, ecx
    add     esi, 2
    mov     byte [esi+eax], 0       ; null-terminate
    push    esi                     ; save path ptr
    add     esi, eax
    ;; Decode blob: 4-byte BE len + data
    mov     eax, [esi]
    bswap   eax
    mov     ecx, eax                ; content length
    add     esi, 4                  ; esi = content data
    push    ecx                     ; save content length
    push    esi                     ; save content ptr
    ;; Open for writing
    push    1                       ; flags = write
    push    dword [esp+16]          ; path (3 pushes ago + current push)
    call    [os_vtable.open]
    add     esp, 8
    test    eax, eax
    js      .write_err
    mov     edi, eax                ; file fd
    ;; Write content
    pop     esi                     ; content ptr
    pop     ecx                     ; content length
    pop     eax                     ; discard path
    push    ecx
    push    esi
    push    edi
    call    [os_vtable.write]
    add     esp, 12
    ;; Close
    push    edi
    call    [os_vtable.close]
    add     esp, 4
    ;; Send WRITE_OK
    push    0
    push    0
    push    byte CMD_WRITE_OK
    push    dword [_srv_client]
    call    proto_send_msg
    add     esp, 16
    jmp     .cmd_loop
.write_err:
    pop     esi
    pop     ecx
    pop     eax
    call    .send_error
    jmp     .cmd_loop

;; ==== NATIVE: ps/kill ====
.do_native:
    movzx   eax, byte [_proto_buf+1]   ; sub-command
    cmp     al, 0x01                    ; ps
    je      .do_ps
    cmp     al, 0x02                    ; kill
    je      .do_kill
    call    .send_error
    jmp     .cmd_loop

.do_ps:
    ;; Execute "ps -eo pid,comm --no-headers" and return output
    push    65536
    push    _srv_execbuf
    push    _srv_ps_cmd
    call    [os_vtable.exec]
    add     esp, 12
    test    eax, eax
    js      .ps_err
    ;; Send as NATIVE_RESP
    push    eax
    push    _srv_execbuf
    push    byte CMD_NATIVE_RESP
    push    dword [_srv_client]
    call    proto_send_msg
    add     esp, 16
    jmp     .cmd_loop
.ps_err:
    call    .send_error
    jmp     .cmd_loop

.do_kill:
    ;; Payload: sub_cmd(1) + u32be(pid)
    mov     eax, [_proto_buf+2]
    bswap   eax                     ; pid

    ;; Build kill command: "kill -9 <pid>"
    ;; Simple approach: format and exec
    push    eax                     ; save pid
    lea     edi, [_srv_infobuf]
    mov     dword [edi], 'kill'
    mov     dword [edi+4], ' -9 '
    add     edi, 8
    pop     eax
    ;; itoa into edi
    push    eax
    push    ebx
    mov     ebx, 10
    xor     ecx, ecx
.kill_itoa:
    xor     edx, edx
    div     ebx
    add     dl, '0'
    push    edx
    inc     ecx
    test    eax, eax
    jnz     .kill_itoa
.kill_pop:
    pop     edx
    mov     [edi], dl
    inc     edi
    dec     ecx
    jnz     .kill_pop
    mov     byte [edi], 0
    pop     ebx
    ;; Execute
    push    512
    push    _srv_execbuf
    push    _srv_infobuf
    call    [os_vtable.exec]
    add     esp, 12
    ;; Send response
    mov     esi, _srv_killed
    cmp     eax, 0
    jge     .kill_ok
    mov     esi, _srv_killfail
.kill_ok:
    call    pm_strlen
    push    eax
    push    esi
    push    byte CMD_NATIVE_RESP
    push    dword [_srv_client]
    call    proto_send_msg
    add     esp, 16
    jmp     .cmd_loop

;; ==== SYNC: delta pull (client sends sigs, server sends M/D/E) ====
.do_sync:
    ;; Payload: encode_str(path) + u32be(sig_count) + sigs[8 bytes each]
    lea     esi, [_proto_buf+1]
    ;; Decode path
    movzx   eax, byte [esi]
    shl     eax, 8
    movzx   ecx, byte [esi+1]
    or      eax, ecx
    add     esi, 2
    mov     byte [esi+eax], 0   ; null-terminate
    push    esi                 ; save path ptr
    add     esi, eax
    ;; Decode sig_count (4-byte BE)
    mov     eax, [esi]
    bswap   eax
    push    eax                 ; save sig_count
    add     esi, 4
    push    esi                 ; save sigs_ptr
    ;; Open file for reading
    push    0                   ; flags = read
    push    dword [esp+16]     ; path (3 pushes + this push = 16)
    call    [os_vtable.open]
    add     esp, 8
    test    eax, eax
    js      .sync_err
    mov     edi, eax            ; file fd
    ;; Call sync_send_delta(client_fd, file_fd, sigs_ptr, sig_count)
    pop     esi                 ; sigs_ptr
    pop     ecx                 ; sig_count
    pop     eax                 ; discard path
    push    ecx                 ; sig_count
    push    esi                 ; sigs_ptr
    push    edi                 ; file_fd
    push    dword [_srv_client] ; client_fd
    call    sync_send_delta
    add     esp, 16
    ;; Close file
    push    edi
    call    [os_vtable.close]
    add     esp, 4
    jmp     .cmd_loop
.sync_err:
    pop     esi
    pop     ecx
    pop     eax
    call    .send_error
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
    ;; Raw debug: write directly via int 0x80 (bypass vtable)
    push    ebx
    mov     eax, 4              ; SYS_WRITE
    mov     ebx, 2              ; stderr
    mov     ecx, _dbg_a1
    mov     edx, 31             ; len of "[auth] waiting for AUTH_REQUEST\n"
    int     0x80
    pop     ebx

    ;; Recv AUTH_REQUEST
    push    dword [_srv_client]
    call    proto_recv_msg
    add     esp, 4

    ;; Raw debug: print recv result
    push    eax
    push    ebx
    mov     ebx, eax            ; save recv result
    mov     eax, 4
    push    ebx                 ; save
    mov     ebx, 2
    mov     ecx, _dbg_a2
    mov     edx, 25
    int     0x80
    pop     ebx                 ; restore recv result
    pop     ebx
    pop     eax

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
    mov     esi, _dbg_a3
    call    pm_stderr

    ;; Recv AUTH_RESPONSE (ignore content)
    push    dword [_srv_client]
    call    proto_recv_msg
    add     esp, 4
    push    eax
    mov     esi, _dbg_a4
    call    pm_stderr
    pop     eax
    test    eax, eax
    jle     .auth_fail

    mov     esi, _dbg_a5
    call    pm_stderr
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
    mov     esi, _dbg_a6
    call    pm_stderr
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
