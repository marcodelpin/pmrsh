;; =============================================================================
;; shell.inc — Interactive shell session (OS-agnostic via vtable)
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; Server: fork /bin/sh with pipes, relay I/O via CMD_SHELL_DATA
;; Uses vtable.exec internally (fork+pipe), but in streaming mode.
;; =============================================================================

CMD_SHELL_REQ   equ 0x80
CMD_SHELL_DATA  equ 0x81

section .bss
    _shell_cmd_buf resb 4096

section .text

;; =============================================================================
;; shell_handle — Server-side: run shell, relay I/O until disconnect
;; Args on stack: (client_fd)
;; For MVP: execute each received CMD_SHELL_DATA as a command via vtable.exec
;; This is not a true interactive shell (no pty) but works for automation.
;; =============================================================================
global shell_handle
shell_handle:
    push    ebx
    push    esi
    mov     ebx, [esp+12]       ; client_fd

.shell_loop:
    ;; Receive command from client
    push    ebx
    call    proto_recv_msg
    add     esp, 4
    test    eax, eax
    jle     .shell_done

    movzx   ecx, byte [_proto_buf]
    cmp     cl, CMD_SHELL_DATA
    jne     .shell_done          ; any non-DATA message ends session

    ;; Payload is the command text
    mov     ecx, eax
    dec     ecx                  ; payload len (minus cmdId)
    lea     esi, [_proto_buf+1]
    mov     byte [esi+ecx], 0    ; null-terminate

    ;; Execute via vtable
    push    65536
    push    _srv_execbuf
    push    esi
    call    [os_vtable.exec]
    add     esp, 12
    test    eax, eax
    js      .shell_loop          ; exec failed, skip

    ;; Send output as CMD_SHELL_DATA
    push    eax                  ; output len
    push    _srv_execbuf
    push    byte CMD_SHELL_DATA
    push    ebx
    call    proto_send_msg
    add     esp, 16
    jmp     .shell_loop

.shell_done:
    pop     esi
    pop     ebx
    ret
