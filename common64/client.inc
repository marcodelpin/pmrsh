;; =============================================================================
;; client.inc — Client mode: full command dispatch (x86_64)
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; Commands: ping, exec, info, ps, kill, push, pull, write, shell, sync
;; =============================================================================

section .data
    _cli_err_conn db "Error: connection failed", 10, 0
    _cli_err_auth db "Error: authentication failed", 10, 0
    _cli_err_noarg db "Error: missing argument", 10, 0
    _cli_pong     db "pong", 10, 0
    _cli_push_ok  db "push complete", 10, 0
    _cli_pull_ok  db "pull complete", 10, 0
    _cli_write_ok db "write complete", 10, 0
    _cli_sync_ok  db "sync complete", 10, 0
    _cli_push_fail db "Error: push failed", 10, 0
    _cli_pull_fail db "Error: pull failed", 10, 0
    _cli_newline  db 10, 0

    ;; Command strings for comparison
    _cmd_ping     db "ping", 0
    _cmd_exec     db "exec", 0
    _cmd_info     db "info", 0
    _cmd_ps       db "ps", 0
    _cmd_kill     db "kill", 0
    _cmd_push     db "push", 0
    _cmd_pull     db "pull", 0
    _cmd_write    db "write", 0
    _cmd_shell    db "shell", 0
    _cmd_sync     db "sync", 0
    _cmd_syncpush db "sync-push", 0
    _cmd_version  db "version", 0
    _cmd_selfupd  db "self-update", 0
    _cmd_ls       db "ls", 0
    _cmd_mkdir    db "mkdir", 0
    _cmd_rm       db "rm", 0
    _cmd_cp       db "cp", 0
    _cmd_cat      db "cat", 0
    _cmd_stat     db "stat", 0
    _sync_tmp_path db "/tmp/.pmash_sync.tmp", 0
    _cli_syncpush_ok db "sync-push complete", 10, 0

section .bss
    _cli_fd       resd 1
    _cli_filebuf  resb 32768

section .text

;; =============================================================================
;; client_run(rdi=host_ip, rsi=port, rdx=cmd_name, rcx=cmd_arg)
;; =============================================================================
global client_run
client_run:
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    mov     r12d, edi              ; host_ip (network order)
    mov     r13d, esi              ; port
    mov     r14, rdx               ; cmd_name
    mov     r15, rcx               ; cmd_arg

    ;; Pre-load auth keys
    call    auth_load_or_gen

    ;; Create socket + connect
    call    [os_vtable.socket]
    test    eax, eax
    js      .conn_err
    mov     [_cli_fd], eax

    mov     edi, eax
    mov     esi, r12d
    mov     edx, r13d
    call    [os_vtable.connect]
    test    eax, eax
    jnz     .conn_err

    ;; TLS handshake — skip for now (server must have certs first)
    ;; TODO: peek first byte from server; if 0x16 → TLS, else plain
    ;; For now, client only does TLS when --tls flag is set (not implemented)
    ;; This ensures backwards compat with plain servers

    ;; Auth handshake
    mov     edi, [_cli_fd]
    call    auth_client_handshake
    test    eax, eax
    jnz     .auth_err

    ;; Dispatch command by comparing strings
    mov     rdi, r14

    ;; "ping"
    lea     rsi, [_cmd_ping]
    call    .cmdcmp
    test    eax, eax
    jz      .cmd_ping

    ;; "exec"
    mov     rdi, r14
    lea     rsi, [_cmd_exec]
    call    .cmdcmp
    test    eax, eax
    jz      .cmd_exec

    ;; "info"
    mov     rdi, r14
    lea     rsi, [_cmd_info]
    call    .cmdcmp
    test    eax, eax
    jz      .cmd_info

    ;; "ps"
    mov     rdi, r14
    lea     rsi, [_cmd_ps]
    call    .cmdcmp
    test    eax, eax
    jz      .cmd_ps

    ;; "kill"
    mov     rdi, r14
    lea     rsi, [_cmd_kill]
    call    .cmdcmp
    test    eax, eax
    jz      .cmd_kill

    ;; "push"
    mov     rdi, r14
    lea     rsi, [_cmd_push]
    call    .cmdcmp
    test    eax, eax
    jz      .cmd_push

    ;; "pull"
    mov     rdi, r14
    lea     rsi, [_cmd_pull]
    call    .cmdcmp
    test    eax, eax
    jz      .cmd_pull

    ;; "write"
    mov     rdi, r14
    lea     rsi, [_cmd_write]
    call    .cmdcmp
    test    eax, eax
    jz      .cmd_write

    ;; "shell"
    mov     rdi, r14
    lea     rsi, [_cmd_shell]
    call    .cmdcmp
    test    eax, eax
    jz      .cmd_shell

    ;; "sync"
    mov     rdi, r14
    lea     rsi, [_cmd_sync]
    call    .cmdcmp
    test    eax, eax
    jz      .cmd_sync

    ;; "sync-push"
    mov     rdi, r14
    lea     rsi, [_cmd_syncpush]
    call    .cmdcmp
    test    eax, eax
    jz      .cmd_sync_push

    ;; "ls" → exec "ls <arg>"
    mov     rdi, r14
    lea     rsi, [_cmd_ls]
    call    .cmdcmp
    test    eax, eax
    jz      .cmd_ls

    ;; "mkdir"
    mov     rdi, r14
    lea     rsi, [_cmd_mkdir]
    call    .cmdcmp
    test    eax, eax
    jz      .cmd_fop_mkdir

    ;; "rm"
    mov     rdi, r14
    lea     rsi, [_cmd_rm]
    call    .cmdcmp
    test    eax, eax
    jz      .cmd_fop_rm

    ;; "cp"
    mov     rdi, r14
    lea     rsi, [_cmd_cp]
    call    .cmdcmp
    test    eax, eax
    jz      .cmd_fop_cp

    ;; "cat"
    mov     rdi, r14
    lea     rsi, [_cmd_cat]
    call    .cmdcmp
    test    eax, eax
    jz      .cmd_fop_cat

    ;; "stat"
    mov     rdi, r14
    lea     rsi, [_cmd_stat]
    call    .cmdcmp
    test    eax, eax
    jz      .cmd_fop_stat

    ;; "version"
    mov     rdi, r14
    lea     rsi, [_cmd_version]
    call    .cmdcmp
    test    eax, eax
    jz      .cmd_info

    ;; Default: treat as exec with cmd_name as command
    jmp     .cmd_exec_implicit

;; ===================== PING =====================
.cmd_ping:
    mov     edi, [_cli_fd]
    mov     sil, CMD_PING
    xor     edx, edx
    xor     ecx, ecx
    call    proto_send_msg
    mov     edi, [_cli_fd]
    call    proto_recv_msg
    lea     rdi, [_cli_pong]
    call    pm_stdout
    jmp     .done

;; ===================== EXEC =====================
.cmd_exec:
    mov     rsi, r15               ; arg = command string
    test    rsi, rsi
    jz      .noarg_err
    jmp     .cmd_exec_send
.cmd_exec_implicit:
    mov     rsi, r14               ; use cmd_name as command
.cmd_exec_send:
    ;; Build EXEC payload: encode_str(cmd) + env_count(0)
    push    rsi
    mov     rdi, rsi
    call    pm_strlen
    mov     ecx, eax               ; cmd length
    pop     rsi
    lea     rdi, [_srv_infobuf]
    ;; 2-byte BE length
    mov     eax, ecx
    shr     eax, 8
    mov     [rdi], al              ; len high
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
    ;; EXEC_RESULT: cmdId(1) + exit_code(4) + blob_len(4) + data
    cmp     eax, 9
    jl      .done
    mov     ecx, eax
    sub     ecx, 9
    jle     .done
    mov     edi, 1
    lea     rsi, [_proto_buf+9]
    mov     edx, ecx
    call    [os_vtable.write]
    jmp     .done

;; ===================== INFO =====================
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
    dec     eax
    mov     edi, 1
    lea     rsi, [_proto_buf+1]
    mov     edx, eax
    call    [os_vtable.write]
    ;; newline
    mov     edi, 1
    lea     rsi, [_cli_newline]
    mov     edx, 1
    call    [os_vtable.write]
    jmp     .done

;; ===================== PS =====================
.cmd_ps:
    lea     rdi, [_srv_infobuf]
    mov     byte [rdi], 0x01       ; NATIVE sub-cmd: ps
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

;; ===================== KILL =====================
.cmd_kill:
    test    r15, r15
    jz      .noarg_err
    ;; Parse PID from arg
    mov     rdi, r15
    call    pm_atoi
    ;; Build NATIVE kill: sub_cmd(1) + u32be(pid)
    lea     rdi, [_srv_infobuf]
    mov     byte [rdi], 0x02       ; NATIVE sub-cmd: kill
    bswap   eax
    mov     [rdi+1], eax
    mov     edi, [_cli_fd]
    mov     sil, CMD_NATIVE
    lea     rdx, [_srv_infobuf]
    mov     ecx, 5
    call    proto_send_msg
    ;; Recv response
    mov     edi, [_cli_fd]
    call    proto_recv_msg
    test    eax, eax
    jle     .done
    dec     eax
    mov     edi, 1
    lea     rsi, [_proto_buf+1]
    mov     edx, eax
    call    [os_vtable.write]
    ;; newline
    mov     edi, 1
    lea     rsi, [_cli_newline]
    mov     edx, 1
    call    [os_vtable.write]
    jmp     .done

;; ===================== PUSH =====================
.cmd_push:
    ;; push <local_path> [remote_path]
    test    r15, r15
    jz      .noarg_err
    ;; Open local file
    mov     rdi, r15               ; local path
    xor     esi, esi               ; read
    call    [os_vtable.open]
    test    eax, eax
    js      .push_fail
    mov     ebx, eax               ; file fd

    ;; Get file size
    mov     edi, ebx
    call    [os_vtable.filesize]
    test    rax, rax
    js      .push_close_fail
    push    rax                    ; save file size

    ;; Build PUSH_START: file_size(8LE) + encode_str(remote_path)
    ;; Use same path for local and remote (simplified)
    lea     rdi, [_srv_infobuf]
    pop     rax                    ; file size
    mov     [rdi], rax             ; 8 bytes LE
    add     rdi, 8
    ;; encode_str: 2-byte BE len + path
    push    r15
    mov     rdi, r15
    call    pm_strlen
    pop     r15
    mov     ecx, eax
    lea     rdi, [_srv_infobuf+8]
    mov     eax, ecx
    shr     eax, 8
    mov     [rdi], al
    mov     [rdi+1], cl
    add     rdi, 2
    mov     rsi, r15
    push    rcx
    rep movsb
    pop     rcx
    add     ecx, 10               ; 8 + 2 + pathlen
    mov     edi, [_cli_fd]
    mov     sil, CMD_PUSH_START
    lea     rdx, [_srv_infobuf]
    call    proto_send_msg

    ;; Send file in chunks
.push_loop:
    mov     edi, ebx               ; file fd
    lea     rsi, [_cli_filebuf]
    mov     edx, 32768
    call    [os_vtable.read]
    test    eax, eax
    jle     .push_end
    ;; Send PUSH_DATA
    mov     ecx, eax
    mov     edi, [_cli_fd]
    mov     sil, CMD_PUSH_DATA
    lea     rdx, [_cli_filebuf]
    call    proto_send_msg
    jmp     .push_loop

.push_end:
    ;; Close file
    mov     edi, ebx
    call    [os_vtable.close]
    ;; Send PUSH_END
    mov     edi, [_cli_fd]
    mov     sil, CMD_PUSH_END
    xor     edx, edx
    xor     ecx, ecx
    call    proto_send_msg
    ;; Wait for PUSH_OK
    mov     edi, [_cli_fd]
    call    proto_recv_msg
    lea     rdi, [_cli_push_ok]
    call    pm_stdout
    jmp     .done

.push_close_fail:
    mov     edi, ebx
    call    [os_vtable.close]
.push_fail:
    lea     rdi, [_cli_push_fail]
    call    pm_stderr
    jmp     .done

;; ===================== PULL =====================
.cmd_pull:
    test    r15, r15
    jz      .noarg_err
    ;; Build PULL_REQ: encode_str(remote_path)
    push    r15
    mov     rdi, r15
    call    pm_strlen
    pop     r15
    mov     ecx, eax
    lea     rdi, [_srv_infobuf]
    mov     eax, ecx
    shr     eax, 8
    mov     [rdi], al
    mov     [rdi+1], cl
    add     rdi, 2
    mov     rsi, r15
    push    rcx
    rep movsb
    pop     rcx
    add     ecx, 2
    mov     edi, [_cli_fd]
    mov     sil, CMD_PULL_REQ
    lea     rdx, [_srv_infobuf]
    call    proto_send_msg

    ;; Open local file for writing (same name)
    mov     rdi, r15
    mov     esi, 1                 ; write
    call    [os_vtable.open]
    test    eax, eax
    js      .pull_fail
    mov     ebx, eax               ; file fd

    ;; Receive chunks until PULL_END
.pull_loop:
    mov     edi, [_cli_fd]
    call    proto_recv_msg
    test    eax, eax
    jle     .pull_close
    movzx   ecx, byte [_proto_buf]
    cmp     cl, CMD_PULL_DATA
    jne     .pull_chk_end
    ;; Write data (skip cmdId byte)
    dec     eax
    mov     edi, ebx
    lea     rsi, [_proto_buf+1]
    mov     edx, eax
    call    [os_vtable.write]
    jmp     .pull_loop
.pull_chk_end:
    cmp     cl, CMD_PULL_END
    je      .pull_close
    cmp     cl, CMD_ERROR
    je      .pull_close_fail
    jmp     .pull_loop
.pull_close:
    mov     edi, ebx
    call    [os_vtable.close]
    lea     rdi, [_cli_pull_ok]
    call    pm_stdout
    jmp     .done
.pull_close_fail:
    mov     edi, ebx
    call    [os_vtable.close]
.pull_fail:
    lea     rdi, [_cli_pull_fail]
    call    pm_stderr
    jmp     .done

;; ===================== WRITE =====================
.cmd_write:
    ;; Format: pmash write "path:content"
    test    r15, r15
    jz      .noarg_err
    ;; Find ':' separator
    mov     rsi, r15
    xor     ecx, ecx
.write_find_sep:
    mov     al, [rsi+rcx]
    test    al, al
    jz      .noarg_err
    cmp     al, ':'
    je      .write_split
    inc     ecx
    jmp     .write_find_sep
.write_split:
    ;; ecx = path length
    ;; r15+ecx+1 = content start
    push    rbx
    mov     ebx, ecx               ; save path length

    ;; Build payload in _srv_infobuf
    lea     rdi, [_srv_infobuf]
    ;; encode_str(path): 2-byte BE len + path bytes
    mov     eax, ebx
    shr     eax, 8
    mov     [rdi], al              ; high byte
    mov     [rdi+1], bl            ; low byte
    add     rdi, 2
    ;; Copy path bytes
    mov     rsi, r15
    mov     ecx, ebx
    rep movsb
    ;; rdi now points past path

    ;; Content = r15 + pathlen + 1 (skip ':')
    lea     rsi, [r15 + rbx + 1]
    ;; Get content length
    push    rdi                    ; save output ptr
    push    rsi                    ; save content ptr
    mov     rdi, rsi
    call    pm_strlen
    pop     rsi                    ; restore content ptr
    pop     rdi                    ; restore output ptr
    mov     ecx, eax               ; content length

    ;; encode_blob: 4-byte BE len + data
    mov     eax, ecx
    bswap   eax
    mov     [rdi], eax
    add     rdi, 4
    rep movsb
    ;; rdi now points past entire payload

    ;; Calculate total payload length
    lea     rax, [_srv_infobuf]
    sub     rdi, rax               ; rdi = total bytes
    mov     ecx, edi               ; payload len (fits in 32-bit)

    mov     edi, [_cli_fd]
    mov     sil, CMD_WRITE
    lea     rdx, [_srv_infobuf]
    call    proto_send_msg
    pop     rbx

    ;; Wait for WRITE_OK
    mov     edi, [_cli_fd]
    call    proto_recv_msg
    test    eax, eax
    jle     .done
    lea     rdi, [_cli_write_ok]
    call    pm_stdout
    jmp     .done

;; ===================== SHELL =====================
.cmd_shell:
    ;; Interactive shell: send commands from cmd_arg, get responses
    ;; If arg provided, send single command
    test    r15, r15
    jz      .noarg_err
    ;; Send CMD_SHELL_REQ first
    mov     edi, [_cli_fd]
    mov     sil, CMD_SHELL_REQ
    xor     edx, edx
    xor     ecx, ecx
    call    proto_send_msg
    ;; Send command as CMD_SHELL_DATA
    push    r15
    mov     rdi, r15
    call    pm_strlen
    pop     r15
    mov     ecx, eax
    mov     edi, [_cli_fd]
    mov     sil, CMD_SHELL_DATA
    mov     rdx, r15
    call    proto_send_msg
    ;; Recv response
    mov     edi, [_cli_fd]
    call    proto_recv_msg
    test    eax, eax
    jle     .done
    dec     eax
    jle     .done
    mov     edi, 1
    lea     rsi, [_proto_buf+1]
    mov     edx, eax
    call    [os_vtable.write]
    jmp     .done

;; ===================== SYNC (delta pull) =====================
.cmd_sync:
    ;; sync <remote_path> — delta pull from server
    test    r15, r15
    jz      .noarg_err
    ;; Open local file for reading to compute signatures
    mov     rdi, r15
    xor     esi, esi               ; read
    call    [os_vtable.open]
    test    eax, eax
    js      .sync_fresh            ; file doesn't exist → fresh pull
    mov     ebx, eax               ; local_read_fd
    ;; Compute block signatures
    mov     edi, ebx
    call    sync_compute_sigs
    push    rax                    ; save block count
    ;; Seek back to start (for M block reads later)
    mov     edi, ebx
    xor     esi, esi
    xor     edx, edx               ; SEEK_SET
    call    [os_vtable.seek]
    pop     rcx                    ; block count

    ;; Build SYNC_REQ: encode_str(path) + u32be(sig_count) + sigs
    push    rbx                    ; save local_read_fd
    push    r15
    mov     rdi, r15
    call    pm_strlen
    pop     r15
    mov     r8d, eax               ; path length
    lea     rdi, [_srv_infobuf]
    mov     eax, r8d
    shr     eax, 8
    mov     [rdi], al
    mov     [rdi+1], r8b
    add     rdi, 2
    mov     rsi, r15
    push    rcx
    mov     ecx, r8d
    rep movsb
    pop     rcx
    ;; u32be(sig_count)
    mov     eax, ecx
    bswap   eax
    mov     [rdi], eax
    add     rdi, 4
    ;; Copy signatures (8 bytes each)
    push    rcx
    shl     ecx, 3
    lea     rsi, [_sync_sigbuf]
    rep movsb
    pop     rcx
    ;; Total payload
    lea     rax, [_srv_infobuf]
    mov     rcx, rdi
    sub     rcx, rax
    mov     edi, [_cli_fd]
    mov     sil, CMD_SYNC_REQ
    lea     rdx, [_srv_infobuf]
    call    proto_send_msg

    ;; Open temp output file for reconstructed content
    lea     rdi, [_sync_tmp_path]
    mov     esi, 1                 ; write
    call    [os_vtable.open]
    test    eax, eax
    js      .sync_apply_fail
    push    rax                    ; save output_fd

    ;; Apply delta: server_fd, local_read_fd, output_fd
    pop     rdx                    ; output_fd
    push    rdx                    ; keep on stack
    pop     r8                     ; output_fd in r8 temporarily
    pop     rbx                    ; local_read_fd
    push    r8                     ; output_fd back on stack
    mov     edi, [_cli_fd]         ; server_fd
    mov     esi, ebx               ; local_read_fd
    mov     edx, r8d               ; output_fd
    call    sync_apply_delta

    ;; Close both files
    pop     r8                     ; output_fd
    push    rax                    ; save result
    mov     edi, ebx               ; close local_read_fd
    call    [os_vtable.close]
    mov     edi, r8d               ; close output_fd
    call    [os_vtable.close]

    pop     rax                    ; delta apply result
    test    eax, eax
    jnz     .sync_apply_fail

    ;; Rename temp → original (atomic replace)
    lea     rdi, [_sync_tmp_path]
    mov     rsi, r15
    call    [os_vtable.rename]

    lea     rdi, [_cli_sync_ok]
    call    pm_stdout
    jmp     .done

.sync_apply_fail:
    ;; Clean up temp file
    lea     rdi, [_sync_tmp_path]
    call    [os_vtable.unlink]
    lea     rdi, [_cli_push_fail]
    call    pm_stderr
    jmp     .done

.sync_fresh:
    ;; File doesn't exist — do a regular pull instead
    jmp     .cmd_pull

;; ===================== SYNC-PUSH (delta push to server) =====================
.cmd_sync_push:
    ;; sync-push <local_path> — push local file delta to server
    test    r15, r15
    jz      .noarg_err

    ;; Send SYNC_PUSH_REQ with path
    push    r15
    mov     rdi, r15
    call    pm_strlen
    pop     r15
    mov     ecx, eax
    lea     rdi, [_srv_infobuf]
    mov     eax, ecx
    shr     eax, 8
    mov     [rdi], al
    mov     [rdi+1], cl
    add     rdi, 2
    mov     rsi, r15
    push    rcx
    rep movsb
    pop     rcx
    add     ecx, 2
    mov     edi, [_cli_fd]
    mov     sil, CMD_SYNC_PUSH_REQ
    lea     rdx, [_srv_infobuf]
    call    proto_send_msg

    ;; Receive SYNC_PUSH_SIGS from server (server's block sigs)
    mov     edi, [_cli_fd]
    call    proto_recv_msg
    test    eax, eax
    jle     .sp_cli_fail
    cmp     byte [_proto_buf], CMD_SYNC_PUSH_SIGS
    jne     .sp_cli_fail

    ;; Parse sig_count + sigs from response
    mov     eax, [_proto_buf+1]
    bswap   eax                    ; sig_count
    mov     r8d, eax               ; save sig_count
    ;; Sigs start at _proto_buf+5
    ;; Copy to _sync_sigbuf for sync_send_delta
    mov     ecx, r8d
    shl     ecx, 3                 ; * 8
    lea     rdi, [_sync_sigbuf]
    lea     rsi, [_proto_buf+5]
    rep movsb

    ;; Open local file for reading
    mov     rdi, r15
    xor     esi, esi
    call    [os_vtable.open]
    test    eax, eax
    js      .sp_cli_fail
    mov     ebx, eax               ; local file fd

    ;; Send delta: reads local blocks, compares with server sigs, sends M/D/E
    mov     edi, [_cli_fd]         ; send to server
    mov     esi, ebx               ; local file fd
    lea     rdx, [_sync_sigbuf]    ; server's sigs
    mov     ecx, r8d               ; sig count
    call    sync_send_delta

    ;; Close local file
    mov     edi, ebx
    call    [os_vtable.close]

    ;; Wait for SYNC_PUSH_OK
    mov     edi, [_cli_fd]
    call    proto_recv_msg
    test    eax, eax
    jle     .sp_cli_fail

    lea     rdi, [_cli_syncpush_ok]
    call    pm_stdout
    jmp     .done

.sp_cli_fail:
    lea     rdi, [_cli_push_fail]
    call    pm_stderr
    jmp     .done

;; ===================== FILEOPS (mkdir/rm/cp/cat/stat) =====================
.cmd_fop_mkdir:
    mov     cl, 0x01
    jmp     .cmd_fop_single
.cmd_fop_rm:
    mov     cl, 0x02
    jmp     .cmd_fop_single
.cmd_fop_cat:
    mov     cl, 0x04
    jmp     .cmd_fop_cat_impl
.cmd_fop_stat:
    mov     cl, 0x06
    jmp     .cmd_fop_single

;; Generic single-path fileop: sub_cmd in cl, path in r15
.cmd_fop_single:
    test    r15, r15
    jz      .noarg_err
    push    rcx                    ; save sub_cmd
    push    r15
    mov     rdi, r15
    call    pm_strlen
    pop     r15
    mov     ecx, eax               ; path length
    pop     rax                    ; sub_cmd in al

    lea     rdi, [_srv_infobuf]
    mov     [rdi], al              ; sub_cmd
    ;; encode_str(path)
    mov     eax, ecx
    shr     eax, 8
    mov     [rdi+1], al
    mov     [rdi+2], cl
    add     rdi, 3
    mov     rsi, r15
    rep movsb
    ;; Total = 1 + 2 + pathlen
    lea     rax, [_srv_infobuf]
    sub     rdi, rax
    mov     ecx, edi
    mov     edi, [_cli_fd]
    mov     sil, CMD_FILEOPS
    lea     rdx, [_srv_infobuf]
    call    proto_send_msg
    ;; Recv response
    mov     edi, [_cli_fd]
    call    proto_recv_msg
    test    eax, eax
    jle     .done
    dec     eax
    jle     .done
    mov     edi, 1
    lea     rsi, [_proto_buf+1]
    mov     edx, eax
    call    [os_vtable.write]
    ;; newline
    mov     edi, 1
    lea     rsi, [_cli_newline]
    mov     edx, 1
    call    [os_vtable.write]
    jmp     .done

;; cat: same as single but prints raw output without newline
.cmd_fop_cat_impl:
    test    r15, r15
    jz      .noarg_err
    push    r15
    mov     rdi, r15
    call    pm_strlen
    pop     r15
    mov     ecx, eax
    lea     rdi, [_srv_infobuf]
    mov     byte [rdi], 0x04       ; cat sub_cmd
    mov     eax, ecx
    shr     eax, 8
    mov     [rdi+1], al
    mov     [rdi+2], cl
    add     rdi, 3
    mov     rsi, r15
    rep movsb
    lea     rax, [_srv_infobuf]
    sub     rdi, rax
    mov     ecx, edi
    mov     edi, [_cli_fd]
    mov     sil, CMD_FILEOPS
    lea     rdx, [_srv_infobuf]
    call    proto_send_msg
    mov     edi, [_cli_fd]
    call    proto_recv_msg
    test    eax, eax
    jle     .done
    dec     eax
    jle     .done
    mov     edi, 1
    lea     rsi, [_proto_buf+1]
    mov     edx, eax
    call    [os_vtable.write]
    jmp     .done

;; cp: needs 2 args — r15 = "src dst" (space-separated) or src, second arg from argv
.cmd_fop_cp:
    ;; For simplicity: use exec "cp <src> <dst>" since cp needs 2 paths
    ;; and our CLI only has 1 arg slot
    test    r15, r15
    jz      .noarg_err
    ;; Build "cp <arg>" and exec it
    lea     rdi, [_srv_infobuf]
    mov     byte [rdi], 'c'
    mov     byte [rdi+1], 'p'
    mov     byte [rdi+2], ' '
    add     rdi, 3
    mov     rsi, r15
    push    rdi
    mov     rdi, r15
    call    pm_strlen
    pop     rdi
    mov     ecx, eax
    mov     rsi, r15
    rep movsb
    mov     byte [rdi], 0
    lea     rsi, [_srv_infobuf]
    jmp     .cmd_exec_send

;; ===================== LS =====================
.cmd_ls:
    ;; ls → exec "ls <arg>" or "ls" if no arg
    lea     rdi, [_srv_infobuf]
    mov     byte [rdi], 'l'
    mov     byte [rdi+1], 's'
    mov     ecx, 2
    test    r15, r15
    jz      .ls_send
    ;; Append " <arg>"
    mov     byte [rdi+2], ' '
    add     rdi, 3
    push    r15
    mov     rdi, r15
    call    pm_strlen
    pop     r15
    mov     ecx, eax
    lea     rdi, [_srv_infobuf+3]
    mov     rsi, r15
    rep movsb
    add     ecx, 3
.ls_send:
    ;; Null-terminate
    lea     rdi, [_srv_infobuf]
    mov     byte [rdi+rcx], 0
    ;; Send as exec
    mov     rsi, rdi
    jmp     .cmd_exec_send

;; ===================== HELPERS =====================
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

.noarg_err:
    lea     rdi, [_cli_err_noarg]
    call    pm_stderr
    mov     edi, 1
    call    [os_vtable.exit]

;; cmdcmp(rdi=str1, rsi=str2) → eax (0=match)
.cmdcmp:
    xor     ecx, ecx
.cc_loop:
    mov     al, [rdi+rcx]
    cmp     al, [rsi+rcx]
    jne     .cc_ne
    test    al, al
    jz      .cc_eq
    inc     ecx
    jmp     .cc_loop
.cc_eq:
    xor     eax, eax
    ret
.cc_ne:
    mov     eax, 1
    ret
