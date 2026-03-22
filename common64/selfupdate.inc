;; =============================================================================
;; selfupdate.inc — Self-update: replace binary + restart (x86_64)
;; Part of pmash — lightweight remote agent
;; =============================================================================

CMD_SELF_UPDATE    equ 0x70
CMD_SELF_UPDATE_OK equ 0x71

section .data
    _su_bak db ".bak", 0
    _su_proc_exe db "/proc/self/exe", 0

section .bss
    _su_path resb 512
    _su_bak_path resb 520

section .text

;; selfupdate_handle(rdi=client_fd, rsi=new_binary_path)
global selfupdate_handle
selfupdate_handle:
    push    rbx
    push    r12
    mov     ebx, edi               ; client_fd
    mov     r12, rsi               ; new_binary_path

    ;; readlink /proc/self/exe
    lea     rdi, [_su_proc_exe]
    lea     rsi, [_su_path]
    mov     edx, 512
    mov     eax, SYS64_READLINK
    syscall
    test    eax, eax
    jle     .fail
    mov     byte [_su_path + rax], 0

    ;; Build backup path: current + ".bak"
    lea     rdi, [_su_bak_path]
    lea     rsi, [_su_path]
    push    rdi
    mov     rdi, rsi
    call    pm_strlen
    pop     rdi
    mov     rcx, rax
    lea     rsi, [_su_path]
    rep movsb
    lea     rsi, [_su_bak]
    mov     ecx, 5
    rep movsb

    ;; Rename current → backup
    lea     rdi, [_su_path]
    lea     rsi, [_su_bak_path]
    call    [os_vtable.rename]

    ;; Rename new → current
    mov     rdi, r12
    lea     rsi, [_su_path]
    call    [os_vtable.rename]

    ;; Send CMD_SELF_UPDATE_OK
    mov     edi, ebx
    mov     sil, CMD_SELF_UPDATE_OK
    xor     edx, edx
    xor     ecx, ecx
    call    proto_send_msg

    ;; Exit (systemd restarts)
    xor     edi, edi
    call    [os_vtable.exit]

.fail:
    pop     r12
    pop     rbx
    ret
