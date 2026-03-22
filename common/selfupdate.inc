;; =============================================================================
;; selfupdate.inc — Self-update: replace binary + restart (OS-agnostic)
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; Protocol: receive new binary path via CMD_SELF_UPDATE,
;; rename current → .bak, rename new → current, exit (systemd restarts)
;; =============================================================================

CMD_SELF_UPDATE    equ 0x70
CMD_SELF_UPDATE_OK equ 0x71

section .data
    _su_bak db ".bak", 0

section .bss
    _su_path resb 512           ; current binary path
    _su_bak_path resb 520       ; current + .bak

section .text

;; =============================================================================
;; selfupdate_handle — Server-side: rename binary and exit
;; Args on stack: (client_fd, new_binary_path)
;; =============================================================================
global selfupdate_handle
selfupdate_handle:
    push    ebx
    push    esi
    push    edi
    mov     ebx, [esp+16]       ; client_fd
    mov     esi, [esp+20]       ; new_binary_path

    ;; Read current exe path from /proc/self/exe
    push    512
    push    _su_path
    push    _su_proc_exe
    call    .readlink
    add     esp, 12
    test    eax, eax
    jle     .fail

    ;; Null-terminate
    mov     byte [_su_path + eax], 0

    ;; Build backup path: current + ".bak"
    lea     edi, [_su_bak_path]
    push    esi
    mov     esi, _su_path
    call    pm_strlen
    mov     ecx, eax
    rep movsb
    mov     esi, _su_bak
    mov     ecx, 5              ; ".bak\0"
    rep movsb
    pop     esi

    ;; Rename current → backup
    push    _su_bak_path
    push    _su_path
    call    [os_vtable.rename]
    add     esp, 8

    ;; Rename new → current
    push    _su_path
    push    esi                  ; new_binary_path
    call    [os_vtable.rename]
    add     esp, 8

    ;; Send CMD_SELF_UPDATE_OK
    push    0
    push    0
    push    byte CMD_SELF_UPDATE_OK
    push    ebx
    call    proto_send_msg
    add     esp, 16

    ;; Exit (systemd/init will restart)
    push    0
    call    [os_vtable.exit]

.fail:
    pop     edi
    pop     esi
    pop     ebx
    ret

;; readlink via syscall 85
.readlink:
    push    ebx
    mov     eax, 85             ; SYS_READLINK
    mov     ebx, [esp+8]        ; path
    mov     ecx, [esp+12]       ; buf
    mov     edx, [esp+16]       ; bufsiz
    int     0x80
    pop     ebx
    ret

section .data
_su_proc_exe db "/proc/self/exe", 0
