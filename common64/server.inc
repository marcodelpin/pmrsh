;; =============================================================================
;; server.inc — Server loop (OS-agnostic via vtable, x86_64)
;; Part of pmash — lightweight remote agent
;; =============================================================================

PUSH_CHUNK equ 32768

section .data
    _srv_version db "pmash 0.2.0", 0
    _srv_err     db "unknown command", 0
    _srv_info_p1 db '{"hostname":"', 0
    _srv_info_p2 db '","version":"pmash 0.2.0","os":"', 0
    _srv_info_p3_w db 'Windows"}', 0
    _srv_info_p3_l db 'Linux"}', 0
    _srv_killed  db "killed", 0
    _srv_killfail db "kill failed", 0
    _srv_file_err db "file error", 0
    _srv_ps_cmd db "ps -eo pid,comm --no-headers 2>/dev/null || tasklist /FO CSV /NH 2>nul", 0
    _srv_sync_tmp db "/tmp/.pmash_sync_srv.tmp", 0
    ;; Safety guard patterns (commands that could kill pmash itself)
    _guard_1 db "kill", 0          ; "kill ... pmash" / "killall pmash"
    _guard_2 db "pkill", 0
    _guard_3 db "killall", 0
    _guard_4 db "systemctl stop pmash", 0
    _guard_5 db "service pmash stop", 0
    _guard_6 db "rm /usr/local/bin/pmash", 0
    _guard_7 db "rm -f /usr/local/bin/pmash", 0
    _guard_blocked db "BLOCKED: command would terminate pmash agent", 0

section .bss
    _srv_hostbuf resb 256
    _srv_infobuf resb 512
    _srv_execbuf resb 65536
    _srv_filebuf resb 32768
    _srv_client  resd 1

section .text

;; server_run(rdi=port)
global server_run
server_run:
    push    rbx
    push    r12
    push    r13
    push    r14
    mov     r12d, edi              ; port

    ;; Create socket
    call    [os_vtable.socket]
    test    eax, eax
    js      .fail
    mov     r14d, eax              ; listen fd (callee-saved, survives all handlers)

    ;; Bind
    mov     edi, r14d
    mov     esi, r12d
    call    [os_vtable.bind]
    test    eax, eax
    jnz     .close_listen

    ;; Listen
    mov     edi, r14d
    mov     esi, 5
    call    [os_vtable.listen]

.accept_loop:
    mov     edi, r14d
    call    [os_vtable.accept]
    test    eax, eax
    js      .accept_loop
    mov     [_srv_client], eax

    ;; Auth
    mov     edi, eax
    call    auth_server_handshake
    test    eax, eax
    jnz     .disconnect

    ;; Command dispatch loop
.cmd_loop:
    mov     edi, [_srv_client]
    call    proto_recv_msg
    test    eax, eax
    jle     .disconnect

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
    cmp     al, CMD_SYNC_PUSH_REQ
    je      .do_sync_push
    cmp     al, CMD_SHELL_REQ
    je      .do_shell
    cmp     al, CMD_SELF_UPDATE
    je      .do_selfupdate
    cmp     al, CMD_PROXY_CONNECT
    je      .do_proxy
    jmp     .do_unknown

.do_ping:
    mov     edi, [_srv_client]
    mov     sil, CMD_PONG
    xor     edx, edx
    xor     ecx, ecx
    call    proto_send_msg
    jmp     .cmd_loop

.do_exec:
    ;; Parse: 2-byte BE string len + command
    movzx   eax, byte [_proto_buf+1]
    shl     eax, 8
    movzx   ecx, byte [_proto_buf+2]
    or      eax, ecx
    lea     rsi, [_proto_buf+3]
    mov     byte [rsi+rax], 0      ; null-terminate

    ;; Safety guard: check for self-destructive commands
    push    rsi
    mov     rdi, rsi
    call    .safety_check
    pop     rsi
    test    eax, eax
    jnz     .exec_blocked

    ;; Execute
    mov     rdi, rsi
    lea     rsi, [_srv_execbuf]
    mov     edx, 65536
    call    [os_vtable.exec]
    test    eax, eax
    js      .exec_err
    ;; Build EXEC_RESULT
    mov     ecx, eax               ; output length
    lea     rdi, [_srv_infobuf]
    mov     dword [rdi], 0         ; exit_code = 0
    mov     eax, ecx
    bswap   eax
    mov     [rdi+4], eax           ; blob length BE
    push    rcx
    lea     rdi, [_srv_infobuf+8]
    lea     rsi, [_srv_execbuf]
    rep movsb
    pop     rcx
    add     ecx, 8
    mov     edi, [_srv_client]
    mov     sil, CMD_EXEC_RESULT
    lea     rdx, [_srv_infobuf]
    call    proto_send_msg
    jmp     .cmd_loop

.exec_blocked:
    ;; Send blocked message as EXEC_RESULT with error
    lea     rdi, [_guard_blocked]
    call    pm_strlen
    mov     ecx, eax
    lea     rdi, [_srv_infobuf]
    mov     dword [rdi], 1         ; exit_code = 1 (error)
    mov     eax, ecx
    bswap   eax
    mov     [rdi+4], eax
    push    rcx
    lea     rdi, [_srv_infobuf+8]
    lea     rsi, [_guard_blocked]
    rep movsb
    pop     rcx
    add     ecx, 8
    mov     edi, [_srv_client]
    mov     sil, CMD_EXEC_RESULT
    lea     rdx, [_srv_infobuf]
    call    proto_send_msg
    jmp     .cmd_loop

.exec_err:
    call    .send_error
    jmp     .cmd_loop

.do_info:
    ;; Get hostname
    lea     rdi, [_srv_hostbuf]
    mov     esi, 255
    call    [os_vtable.hostname]
    ;; Build JSON
    lea     rdi, [_srv_infobuf]
    lea     rsi, [_srv_info_p1]
    call    .strcpy_rdi
    lea     rsi, [_srv_hostbuf]
    call    .strcpy_rdi
    lea     rsi, [_srv_info_p2]
    call    .strcpy_rdi
    cmp     dword [_os_type], OS_WINDOWS
    je      .info_win
    lea     rsi, [_srv_info_p3_l]
    jmp     .info_os_done
.info_win:
    lea     rsi, [_srv_info_p3_w]
.info_os_done:
    call    .strcpy_rdi
    ;; Calculate length
    lea     rax, [_srv_infobuf]
    sub     rdi, rax
    mov     ecx, edi               ; len
    mov     edi, [_srv_client]
    mov     sil, CMD_INFO_RESP
    lea     rdx, [_srv_infobuf]
    call    proto_send_msg
    jmp     .cmd_loop

;; ==== PUSH: receive file ====
.do_push:
    lea     rsi, [_proto_buf+1]
    add     rsi, 8                 ; skip file_size
    movzx   eax, byte [rsi]
    shl     eax, 8
    movzx   ecx, byte [rsi+1]
    or      eax, ecx
    add     rsi, 2
    mov     byte [rsi+rax], 0
    mov     rdi, rsi
    mov     esi, 1                 ; write
    call    [os_vtable.open]
    test    eax, eax
    js      .push_err
    mov     r13d, eax              ; file fd
.push_recv:
    mov     edi, [_srv_client]
    call    proto_recv_msg
    test    eax, eax
    jle     .push_close
    movzx   ecx, byte [_proto_buf]
    cmp     cl, CMD_PUSH_DATA
    jne     .push_chk_end
    dec     eax
    mov     edi, r13d
    lea     rsi, [_proto_buf+1]
    mov     edx, eax
    call    [os_vtable.write]
    jmp     .push_recv
.push_chk_end:
    cmp     cl, CMD_PUSH_END
    je      .push_close
    jmp     .push_recv
.push_close:
    mov     edi, r13d
    call    [os_vtable.close]
    mov     edi, [_srv_client]
    mov     sil, CMD_PUSH_OK
    xor     edx, edx
    xor     ecx, ecx
    call    proto_send_msg
    jmp     .cmd_loop
.push_err:
    call    .send_error
    jmp     .cmd_loop

;; ==== PULL: send file ====
.do_pull:
    lea     rsi, [_proto_buf+1]
    movzx   eax, byte [rsi]
    shl     eax, 8
    movzx   ecx, byte [rsi+1]
    or      eax, ecx
    add     rsi, 2
    mov     byte [rsi+rax], 0
    mov     rdi, rsi
    xor     esi, esi               ; read
    call    [os_vtable.open]
    test    eax, eax
    js      .pull_err
    mov     r13d, eax
.pull_loop:
    mov     edi, r13d
    lea     rsi, [_srv_filebuf]
    mov     edx, PUSH_CHUNK
    call    [os_vtable.read]
    test    eax, eax
    jle     .pull_end
    mov     edi, [_srv_client]
    mov     sil, CMD_PULL_DATA
    lea     rdx, [_srv_filebuf]
    mov     ecx, eax
    call    proto_send_msg
    jmp     .pull_loop
.pull_end:
    mov     edi, r13d
    call    [os_vtable.close]
    mov     edi, [_srv_client]
    mov     sil, CMD_PULL_END
    xor     edx, edx
    xor     ecx, ecx
    call    proto_send_msg
    jmp     .cmd_loop
.pull_err:
    call    .send_error
    jmp     .cmd_loop

;; ==== WRITE ====
.do_write:
    lea     rsi, [_proto_buf+1]
    movzx   eax, byte [rsi]
    shl     eax, 8
    movzx   ecx, byte [rsi+1]
    or      eax, ecx
    add     rsi, 2
    mov     byte [rsi+rax], 0
    push    rsi                    ; path
    add     rsi, rax
    mov     eax, [rsi]
    bswap   eax
    mov     ecx, eax               ; content length
    add     rsi, 4                 ; content data
    push    rcx
    push    rsi                    ; content ptr
    ;; Open for writing
    pop     r8                     ; content ptr (saved for later)
    pop     r9                     ; content len
    pop     rdi                    ; path
    push    r8
    push    r9
    mov     esi, 1
    call    [os_vtable.open]
    test    eax, eax
    js      .write_err
    mov     r13d, eax
    pop     rdx                    ; content len
    pop     rsi                    ; content ptr
    mov     edi, r13d
    call    [os_vtable.write]
    mov     edi, r13d
    call    [os_vtable.close]
    mov     edi, [_srv_client]
    mov     sil, CMD_WRITE_OK
    xor     edx, edx
    xor     ecx, ecx
    call    proto_send_msg
    jmp     .cmd_loop
.write_err:
    pop     rax
    pop     rax
    call    .send_error
    jmp     .cmd_loop

;; ==== NATIVE ====
.do_native:
    movzx   eax, byte [_proto_buf+1]
    cmp     al, 0x01
    je      .do_ps
    cmp     al, 0x02
    je      .do_kill
    call    .send_error
    jmp     .cmd_loop

.do_ps:
    lea     rdi, [_srv_ps_cmd]
    lea     rsi, [_srv_execbuf]
    mov     edx, 65536
    call    [os_vtable.exec]
    test    eax, eax
    js      .ps_err
    mov     edi, [_srv_client]
    mov     sil, CMD_NATIVE_RESP
    lea     rdx, [_srv_execbuf]
    mov     ecx, eax
    call    proto_send_msg
    jmp     .cmd_loop
.ps_err:
    call    .send_error
    jmp     .cmd_loop

.do_kill:
    mov     eax, [_proto_buf+2]
    bswap   eax                    ; pid
    ;; Build "kill -9 <pid>"
    lea     rdi, [_srv_infobuf]
    mov     dword [rdi], 'kill'
    mov     dword [rdi+4], ' -9 '
    add     rdi, 8
    ;; itoa
    push    rbx
    mov     ebx, 10
    xor     ecx, ecx
.kill_itoa:
    xor     edx, edx
    div     ebx
    add     dl, '0'
    push    rdx
    inc     ecx
    test    eax, eax
    jnz     .kill_itoa
.kill_pop:
    pop     rdx
    mov     [rdi], dl
    inc     rdi
    dec     ecx
    jnz     .kill_pop
    mov     byte [rdi], 0
    pop     rbx
    ;; Execute
    lea     rdi, [_srv_infobuf]
    lea     rsi, [_srv_execbuf]
    mov     edx, 512
    call    [os_vtable.exec]
    lea     rsi, [_srv_killed]
    cmp     eax, 0
    jge     .kill_ok
    lea     rsi, [_srv_killfail]
.kill_ok:
    ;; rsi = result string ptr
    push    rsi                    ; save string ptr
    mov     rdi, rsi
    call    pm_strlen
    mov     ecx, eax               ; len
    pop     rdx                    ; string ptr
    mov     edi, [_srv_client]
    mov     sil, CMD_NATIVE_RESP
    call    proto_send_msg
    jmp     .cmd_loop

;; ==== SYNC ====
.do_sync:
    lea     rsi, [_proto_buf+1]
    movzx   eax, byte [rsi]
    shl     eax, 8
    movzx   ecx, byte [rsi+1]
    or      eax, ecx
    add     rsi, 2
    mov     byte [rsi+rax], 0
    push    rsi                    ; path
    add     rsi, rax
    mov     eax, [rsi]
    bswap   eax
    push    rax                    ; sig_count
    add     rsi, 4
    push    rsi                    ; sigs_ptr
    ;; Open file
    pop     r8                     ; sigs_ptr
    pop     r9                     ; sig_count
    pop     rdi                    ; path
    push    r8
    push    r9
    xor     esi, esi
    call    [os_vtable.open]
    test    eax, eax
    js      .sync_err
    mov     r13d, eax              ; file fd
    pop     rcx                    ; sig_count
    pop     rdx                    ; sigs_ptr
    mov     edi, [_srv_client]
    mov     esi, r13d
    call    sync_send_delta
    mov     edi, r13d
    call    [os_vtable.close]
    jmp     .cmd_loop
.sync_err:
    pop     rax
    pop     rax
    call    .send_error
    jmp     .cmd_loop

;; ==== SYNC-PUSH: client sends delta to update server's file ====
.do_sync_push:
    ;; Payload: encode_str(path)
    lea     rsi, [_proto_buf+1]
    movzx   eax, byte [rsi]
    shl     eax, 8
    movzx   ecx, byte [rsi+1]
    or      eax, ecx
    add     rsi, 2
    mov     byte [rsi+rax], 0      ; null-terminate path
    push    rsi                    ; save path ptr

    ;; Open server's file for reading (to compute sigs)
    mov     rdi, rsi
    xor     esi, esi               ; read
    call    [os_vtable.open]
    test    eax, eax
    js      .sp_no_local           ; file doesn't exist — sig_count=0
    mov     r13d, eax              ; local_read_fd

    ;; Compute sigs
    mov     edi, r13d
    call    sync_compute_sigs
    mov     ebx, eax               ; sig_count
    ;; Seek back to start
    mov     edi, r13d
    xor     esi, esi
    xor     edx, edx
    call    [os_vtable.seek]
    jmp     .sp_send_sigs

.sp_no_local:
    xor     ebx, ebx              ; 0 sigs
    mov     r13d, -1               ; no local file

.sp_send_sigs:
    ;; Send CMD_SYNC_PUSH_SIGS: u32be(sig_count) + sigs
    lea     rdi, [_srv_infobuf]
    mov     eax, ebx
    bswap   eax
    mov     [rdi], eax
    add     rdi, 4
    ;; Copy sigs
    mov     ecx, ebx
    shl     ecx, 3                 ; * 8
    push    rcx
    lea     rsi, [_sync_sigbuf]
    rep movsb
    pop     rcx
    add     ecx, 4                 ; total = 4 + sigs_bytes
    mov     edi, [_srv_client]
    mov     sil, CMD_SYNC_PUSH_SIGS
    lea     rdx, [_srv_infobuf]
    call    proto_send_msg

    ;; Open temp output for reconstruction
    pop     rsi                    ; path ptr
    push    rsi                    ; keep for rename
    lea     rdi, [_srv_sync_tmp]
    mov     esi, 1                 ; write
    call    [os_vtable.open]
    test    eax, eax
    js      .sp_err
    push    rax                    ; output_fd

    ;; Receive M/D/E from client via sync_apply_delta
    pop     rdx                    ; output_fd
    push    rdx
    mov     edi, [_srv_client]     ; server reads from client
    mov     esi, r13d              ; local_read_fd (-1 if no file)
    call    sync_apply_delta

    ;; Close files
    pop     r8                     ; output_fd
    push    rax                    ; save result
    cmp     r13d, -1
    je      .sp_no_close_local
    mov     edi, r13d
    call    [os_vtable.close]
.sp_no_close_local:
    mov     edi, r8d
    call    [os_vtable.close]

    pop     rax
    test    eax, eax
    jnz     .sp_err2

    ;; Rename temp → original
    pop     rsi                    ; original path
    lea     rdi, [_srv_sync_tmp]
    call    [os_vtable.rename]

    ;; Send SYNC_PUSH_OK
    mov     edi, [_srv_client]
    mov     sil, CMD_SYNC_PUSH_OK
    xor     edx, edx
    xor     ecx, ecx
    call    proto_send_msg
    jmp     .cmd_loop

.sp_err2:
    pop     rax                    ; discard path
.sp_err:
    ;; Clean up temp
    lea     rdi, [_srv_sync_tmp]
    call    [os_vtable.unlink]
    call    .send_error
    jmp     .cmd_loop

.do_selfupdate:
    lea     rsi, [_proto_buf+1]
    mov     edi, [_srv_client]
    call    selfupdate_handle
    jmp     .cmd_loop

.do_proxy:
    mov     edi, [_srv_client]
    call    proxy_handle
    jmp     .disconnect

.do_shell:
    mov     edi, [_srv_client]
    call    shell_handle
    jmp     .cmd_loop

.do_unknown:
    call    .send_error
    jmp     .cmd_loop

.disconnect:
    mov     edi, [_srv_client]
    call    [os_vtable.closesock]
    jmp     .accept_loop

.close_listen:
    mov     edi, r14d
    call    [os_vtable.closesock]
.fail:
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

;; --- Helper: send error ---
.send_error:
    push    rbx
    lea     rdi, [_srv_infobuf]
    mov     byte [rdi], 0
    mov     byte [rdi+1], 15
    lea     rsi, [_srv_err]
    lea     rdi, [_srv_infobuf+2]
    mov     ecx, 15
    rep movsb
    mov     edi, [_srv_client]
    mov     sil, CMD_ERROR
    lea     rdx, [_srv_infobuf]
    mov     ecx, 17
    call    proto_send_msg
    pop     rbx
    ret

;; --- Helper: safety check for self-destructive commands ---
;; rdi = command string → rax = 0 (safe) or 1 (blocked)
.safety_check:
    push    rbx
    push    r12
    mov     r12, rdi               ; save command ptr

    ;; Check if command contains "pmash" — if not, it's safe
    mov     rdi, r12
    lea     rsi, [_srv_version + 0] ; "pmash" — first 5 chars
    call    .strstr_pmash
    test    eax, eax
    jz      .sc_safe               ; "pmash" not in command → safe

    ;; Command mentions "pmash" — check if it's a kill/stop/rm pattern
    ;; Check "systemctl stop pmash"
    mov     rdi, r12
    lea     rsi, [_guard_4]
    call    .strstr
    test    eax, eax
    jnz     .sc_blocked

    ;; Check "service pmash stop"
    mov     rdi, r12
    lea     rsi, [_guard_5]
    call    .strstr
    test    eax, eax
    jnz     .sc_blocked

    ;; Check "rm /usr/local/bin/pmash"
    mov     rdi, r12
    lea     rsi, [_guard_6]
    call    .strstr
    test    eax, eax
    jnz     .sc_blocked

    mov     rdi, r12
    lea     rsi, [_guard_7]
    call    .strstr
    test    eax, eax
    jnz     .sc_blocked

    ;; Check "killall pmash" or "pkill pmash"
    mov     rdi, r12
    lea     rsi, [_guard_3]        ; "killall"
    call    .strstr
    test    eax, eax
    jnz     .sc_blocked

    mov     rdi, r12
    lea     rsi, [_guard_2]        ; "pkill"
    call    .strstr
    test    eax, eax
    jnz     .sc_blocked

.sc_safe:
    xor     eax, eax
    pop     r12
    pop     rbx
    ret
.sc_blocked:
    mov     eax, 1
    pop     r12
    pop     rbx
    ret

;; strstr_pmash: check if rdi contains "pmash"
.strstr_pmash:
    push    rbx
    xor     ebx, ebx
.sp_loop:
    cmp     byte [rdi+rbx], 0
    je      .sp_no
    cmp     byte [rdi+rbx], 'p'
    jne     .sp_next
    cmp     byte [rdi+rbx+1], 'm'
    jne     .sp_next
    cmp     byte [rdi+rbx+2], 'a'
    jne     .sp_next
    cmp     byte [rdi+rbx+3], 's'
    jne     .sp_next
    cmp     byte [rdi+rbx+4], 'h'
    jne     .sp_next
    mov     eax, 1
    pop     rbx
    ret
.sp_next:
    inc     ebx
    jmp     .sp_loop
.sp_no:
    xor     eax, eax
    pop     rbx
    ret

;; strstr: check if rdi contains rsi substring → eax=1 found, 0 not
.strstr:
    push    rbx
    push    r12
    mov     r12, rsi               ; needle
    xor     ebx, ebx               ; haystack offset
.ss_outer:
    cmp     byte [rdi+rbx], 0
    je      .ss_no
    xor     ecx, ecx               ; needle offset
.ss_inner:
    cmp     byte [r12+rcx], 0
    je      .ss_yes                ; end of needle = full match
    lea     rax, [rdi+rbx]
    mov     al, [rax+rcx]
    cmp     al, 0
    je      .ss_no
    cmp     al, [r12+rcx]
    jne     .ss_next
    inc     ecx
    jmp     .ss_inner
.ss_next:
    inc     ebx
    jmp     .ss_outer
.ss_yes:
    mov     eax, 1
    pop     r12
    pop     rbx
    ret
.ss_no:
    xor     eax, eax
    pop     r12
    pop     rbx
    ret

;; --- Helper: copy ASCIIZ string rsi→rdi, advance rdi ---
.strcpy_rdi:
.sc_loop:
    lodsb
    test    al, al
    jz      .sc_done
    stosb
    jmp     .sc_loop
.sc_done:
    ret
