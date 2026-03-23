;; =============================================================================
;; fileops.inc — Built-in file operations without exec (x86_64)
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; Direct vtable calls instead of fork+exec — faster, no shell overhead.
;; CMD_FILEOPS (0xB5) with sub-commands:
;;   0x01 = mkdir <path>
;;   0x02 = rm <path> (unlink)
;;   0x03 = cp <src> <dst>
;;   0x04 = cat <path> (read file, return content)
;;   0x05 = ls <path> (via exec fallback — readdir not in vtable)
;;   0x06 = stat <path> (file size)
;; =============================================================================

CMD_FILEOPS      equ 0xB5
CMD_FILEOPS_RESP equ 0xB6

section .data
    _fop_ok     db "ok", 0
    _fop_fail   db "error", 0

section .bss
    _fop_buf    resb 65536

section .text

;; =============================================================================
;; fileops_handle(rdi=client_fd) — Server-side: dispatch file operation
;; Payload in _proto_buf: [cmdId][sub_cmd(1)][encode_str(path)][optional args]
;; =============================================================================
global fileops_handle
fileops_handle:
    push    rbx
    push    r12
    push    r13
    mov     ebx, edi               ; client_fd

    movzx   eax, byte [_proto_buf+1]   ; sub-command

    cmp     al, 0x01
    je      .fop_mkdir
    cmp     al, 0x02
    je      .fop_rm
    cmp     al, 0x03
    je      .fop_cp
    cmp     al, 0x04
    je      .fop_cat
    cmp     al, 0x06
    je      .fop_stat
    jmp     .fop_err

;; --- MKDIR ---
.fop_mkdir:
    lea     rsi, [_proto_buf+2]
    call    .decode_str            ; rsi = path, ecx = len
    mov     byte [rsi+rcx], 0
    mov     rdi, rsi
    call    [os_vtable.mkdir]
    jmp     .fop_reply_ok

;; --- RM (unlink) ---
.fop_rm:
    lea     rsi, [_proto_buf+2]
    call    .decode_str
    mov     byte [rsi+rcx], 0
    mov     rdi, rsi
    call    [os_vtable.unlink]
    test    eax, eax
    js      .fop_err
    jmp     .fop_reply_ok

;; --- CP (copy file) ---
.fop_cp:
    lea     rsi, [_proto_buf+2]
    call    .decode_str            ; src path
    mov     byte [rsi+rcx], 0
    push    rsi                    ; save src
    add     rsi, rcx               ; advance past src
    call    .decode_str            ; dst path
    mov     byte [rsi+rcx], 0
    mov     r12, rsi               ; dst
    pop     rdi                    ; src
    ;; Open src for reading
    xor     esi, esi
    call    [os_vtable.open]
    test    eax, eax
    js      .fop_err
    mov     r13d, eax              ; src fd
    ;; Open dst for writing
    mov     rdi, r12
    mov     esi, 1
    call    [os_vtable.open]
    test    eax, eax
    js      .fop_cp_close_src
    mov     r12d, eax              ; dst fd
    ;; Copy loop
.fop_cp_loop:
    mov     edi, r13d
    lea     rsi, [_fop_buf]
    mov     edx, 65536
    call    [os_vtable.read]
    test    eax, eax
    jle     .fop_cp_done
    mov     edi, r12d
    lea     rsi, [_fop_buf]
    mov     edx, eax
    call    [os_vtable.write]
    jmp     .fop_cp_loop
.fop_cp_done:
    mov     edi, r12d
    call    [os_vtable.close]
.fop_cp_close_src:
    mov     edi, r13d
    call    [os_vtable.close]
    jmp     .fop_reply_ok

;; --- CAT (read file content) ---
.fop_cat:
    lea     rsi, [_proto_buf+2]
    call    .decode_str
    mov     byte [rsi+rcx], 0
    mov     rdi, rsi
    xor     esi, esi               ; read
    call    [os_vtable.open]
    test    eax, eax
    js      .fop_err
    mov     r13d, eax              ; fd
    ;; Read file content
    mov     edi, r13d
    lea     rsi, [_fop_buf]
    mov     edx, 65536
    call    [os_vtable.read]
    push    rax                    ; save bytes read
    mov     edi, r13d
    call    [os_vtable.close]
    pop     rcx                    ; bytes
    test    ecx, ecx
    jle     .fop_err
    ;; Send content as response
    mov     edi, ebx
    mov     sil, CMD_FILEOPS_RESP
    lea     rdx, [_fop_buf]
    call    proto_send_msg
    jmp     .fop_done

;; --- STAT (file size) ---
.fop_stat:
    lea     rsi, [_proto_buf+2]
    call    .decode_str
    mov     byte [rsi+rcx], 0
    mov     rdi, rsi
    xor     esi, esi
    call    [os_vtable.open]
    test    eax, eax
    js      .fop_err
    mov     r13d, eax
    mov     edi, r13d
    call    [os_vtable.filesize]
    push    rax
    mov     edi, r13d
    call    [os_vtable.close]
    pop     rax
    ;; Return size as 8-byte LE in response
    lea     rdi, [_fop_buf]
    mov     [rdi], rax
    mov     edi, ebx
    mov     sil, CMD_FILEOPS_RESP
    lea     rdx, [_fop_buf]
    mov     ecx, 8
    call    proto_send_msg
    jmp     .fop_done

;; --- Response helpers ---
.fop_reply_ok:
    mov     edi, ebx
    mov     sil, CMD_FILEOPS_RESP
    lea     rdx, [_fop_ok]
    mov     ecx, 2
    call    proto_send_msg
    jmp     .fop_done

.fop_err:
    mov     edi, ebx
    mov     sil, CMD_FILEOPS_RESP
    lea     rdx, [_fop_fail]
    mov     ecx, 5
    call    proto_send_msg

.fop_done:
    pop     r13
    pop     r12
    pop     rbx
    ret

;; decode_str: rsi points to 2-byte BE len + string
;; Returns: rsi = string ptr, ecx = string length
.decode_str:
    movzx   eax, byte [rsi]
    shl     eax, 8
    movzx   ecx, byte [rsi+1]
    or      ecx, eax
    add     rsi, 2
    ret
