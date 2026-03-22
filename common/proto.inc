;; =============================================================================
;; proto.inc — Binary wire protocol (OS-agnostic via vtable)
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; Wire format: [4-byte BE length][1-byte cmdId][payload]
;; Uses os_vtable.send/recv for I/O — works on any platform.
;; =============================================================================

;; Command IDs (must match all pmash implementations)
CMD_AUTH_REQUEST    equ 0x01
CMD_AUTH_CHALLENGE  equ 0x02
CMD_AUTH_RESPONSE   equ 0x03
CMD_AUTH_OK         equ 0x04
CMD_AUTH_FAIL       equ 0x05
CMD_EXEC            equ 0x10
CMD_EXEC_RESULT     equ 0x11
CMD_PUSH_START      equ 0x20
CMD_PUSH_DATA       equ 0x21
CMD_PUSH_END        equ 0x22
CMD_PUSH_OK         equ 0x23
CMD_PULL_REQ        equ 0x30
CMD_PULL_DATA       equ 0x31
CMD_PULL_END        equ 0x32
CMD_INFO_REQ        equ 0x40
CMD_INFO_RESP       equ 0x41
CMD_PING            equ 0x50
CMD_PONG            equ 0x51
CMD_WRITE           equ 0xA0
CMD_WRITE_OK        equ 0xA1
CMD_NATIVE          equ 0xB0
CMD_NATIVE_RESP     equ 0xB1
CMD_INPUT           equ 0xC0
CMD_INPUT_RESP      equ 0xC1
CMD_ERROR           equ 0xFF

section .bss
    _proto_hdr  resb 4           ; 4-byte length header
    _proto_buf  resb 65536       ; message buffer

section .text


;; =============================================================================
;; proto_send_all — Write exactly N bytes to fd (handles partial writes)
;; Args on stack: (fd, buf, len)
;; =============================================================================
global proto_send_all
proto_send_all:
    push    ebx
    push    esi
    push    edi
    mov     edi, [esp+16]       ; fd
    mov     esi, [esp+20]       ; buf
    mov     ebx, [esp+24]       ; len
.loop:
    test    ebx, ebx
    jle     .done
    push    ebx                 ; len
    push    esi                 ; buf
    push    edi                 ; fd
    call    [os_vtable.send]
    add     esp, 12
    test    eax, eax
    jle     .err
    add     esi, eax
    sub     ebx, eax
    jmp     .loop
.done:
    xor     eax, eax
    pop     edi
    pop     esi
    pop     ebx
    ret
.err:
    mov     eax, -1
    pop     edi
    pop     esi
    pop     ebx
    ret

;; =============================================================================
;; proto_recv_all — Read exactly N bytes from fd
;; Args on stack: (fd, buf, len) → eax = bytes read
;; =============================================================================
global proto_recv_all
proto_recv_all:
    push    ebx
    push    esi
    push    edi
    push    ebp                 ; use ebp as total counter (preserved across calls)
    mov     edi, [esp+20]       ; fd (ret+4 pushes = 20)
    mov     esi, [esp+24]       ; buf
    mov     ebx, [esp+28]       ; len
    xor     ebp, ebp            ; total read
.loop:
    test    ebx, ebx
    jle     .done
    push    ebx
    push    esi
    push    edi
    call    [os_vtable.recv]
    add     esp, 12
    test    eax, eax
    jle     .done_partial
    add     esi, eax
    add     ebp, eax
    sub     ebx, eax
    jmp     .loop
.done:
    mov     eax, ebp
    pop     ebp
    pop     edi
    pop     esi
    pop     ebx
    ret
.done_partial:
    mov     eax, ebp
    pop     ebp
    pop     edi
    pop     esi
    pop     ebx
    ret

;; =============================================================================
;; proto_send_msg — Send [4-byte BE len][cmdId][payload]
;; Args on stack: (fd, cmdId, payload_ptr, payload_len)
;; =============================================================================
global proto_send_msg
proto_send_msg:
    push    ebx
    push    esi
    mov     ebx, [esp+12]       ; fd
    mov     cl, [esp+16]        ; cmdId
    mov     esi, [esp+20]       ; payload ptr
    mov     edx, [esp+24]       ; payload len

    ;; Build message: [cmdId][payload] in _proto_buf
    mov     [_proto_buf], cl
    test    edx, edx
    jz      .send
    push    edx
    push    ecx                 ; save cmdId area
    lea     edi, [_proto_buf+1]
    mov     ecx, edx
    push    esi
    rep movsb
    pop     esi
    pop     ecx
    pop     edx
.send:
    ;; Total message size = 1 + payload_len
    lea     eax, [edx+1]
    push    eax                 ; save total msg size (edx clobbered by send_all)

    ;; Write 4-byte BE length header
    bswap   eax
    mov     [_proto_hdr], eax
    push    4
    push    _proto_hdr
    push    ebx
    call    proto_send_all
    add     esp, 12
    test    eax, eax
    jnz     .fail2

    ;; Write message body
    pop     eax                 ; restore total msg size
    push    eax
    push    _proto_buf
    push    ebx
    call    proto_send_all
    add     esp, 12

    pop     esi
    pop     ebx
    ret
.fail2:
    pop     eax                 ; discard saved msg size
.fail:
    mov     eax, -1
    pop     esi
    pop     ebx
    ret

;; =============================================================================
;; proto_recv_msg — Receive [4-byte BE len][message]
;; Args on stack: (fd)
;; Returns: eax = message length (data in _proto_buf), -1 on error
;; =============================================================================
global proto_recv_msg
proto_recv_msg:
    push    ebx
    mov     ebx, [esp+8]        ; fd

    ;; Read 4-byte header
    push    4
    push    _proto_hdr
    push    ebx
    call    proto_recv_all
    add     esp, 12
    cmp     eax, 4
    jne     .fail

    ;; Decode BE length
    mov     eax, [_proto_hdr]
    bswap   eax
    cmp     eax, 65536
    ja      .fail
    test    eax, eax
    jz      .fail

    ;; Read payload
    push    eax
    push    _proto_buf
    push    ebx
    call    proto_recv_all
    add     esp, 12
    ;; eax = bytes read = message length
    pop     ebx
    ret

.fail:
    mov     eax, -1
    pop     ebx
    ret
