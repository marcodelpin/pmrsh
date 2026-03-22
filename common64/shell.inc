;; =============================================================================
;; shell.inc — Interactive shell session (OS-agnostic via vtable, x86_64)
;; Part of pmash — lightweight remote agent
;; =============================================================================

CMD_SHELL_REQ   equ 0x80
CMD_SHELL_DATA  equ 0x81

section .text

;; shell_handle(rdi=client_fd)
global shell_handle
shell_handle:
    push    rbx
    mov     ebx, edi               ; client_fd

.shell_loop:
    mov     edi, ebx
    call    proto_recv_msg
    test    eax, eax
    jle     .shell_done

    movzx   ecx, byte [_proto_buf]
    cmp     cl, CMD_SHELL_DATA
    jne     .shell_done

    ;; Payload is the command text
    mov     ecx, eax
    dec     ecx                    ; minus cmdId
    lea     rsi, [_proto_buf+1]
    mov     byte [rsi+rcx], 0     ; null-terminate

    ;; Execute via vtable
    mov     rdi, rsi               ; cmd
    lea     rsi, [_srv_execbuf]    ; outbuf
    mov     edx, 65536             ; outbufsize
    call    [os_vtable.exec]
    test    eax, eax
    js      .shell_loop

    ;; Send output as CMD_SHELL_DATA
    mov     edi, ebx
    mov     sil, CMD_SHELL_DATA
    lea     rdx, [_srv_execbuf]
    mov     ecx, eax
    call    proto_send_msg
    jmp     .shell_loop

.shell_done:
    pop     rbx
    ret
