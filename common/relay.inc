;; =============================================================================
;; relay.inc — Rendezvous DeviceID resolution (OS-agnostic via vtable)
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; Flow: RegisterPeer → PunchHoleRequest → parse PunchHoleResponse
;; Uses common/protobuf.inc for message encoding.
;; UDP send/recv via raw syscalls (not in vtable — UDP is specialized).
;; =============================================================================

;; RendezvousMessage envelope field numbers
RDV_REGISTER_PEER          equ 6
RDV_PUNCH_HOLE_REQUEST     equ 8
RDV_PUNCH_HOLE_RESPONSE    equ 11
RDV_FETCH_LOCAL_ADDR       equ 12
RDV_PORT                   equ 21116

section .data
    _rdv_id     db "pmash-client", 0
    _rdv_ver    db "1.2.7", 0
    _rdv_fail   db "rendezvous failed", 0

section .bss
    _rdv_buf    resb 4096
    _rdv_submsg resb 1024

section .text

;; =============================================================================
;; relay_resolve — Resolve DeviceID via hbbs (stub for unified server)
;; Full implementation in asm/include/relay.inc (Windows MASM).
;; The unified server doesn't need client-side relay — it IS the target.
;; This stub exists for the vtable-based client (future).
;; =============================================================================
global relay_resolve
relay_resolve:
    ;; Not implemented in server — server doesn't resolve DeviceIDs
    ;; Client-side relay will be added when unified client is built
    mov     eax, -1
    ret

;; =============================================================================
;; relay_register — Register this server with hbbs rendezvous
;; Args on stack: (rdv_server_ip, rdv_port, device_id)
;; Sends RegisterPeer message via UDP to hbbs.
;; This allows the server to be discoverable by clients.
;; =============================================================================
global relay_register
relay_register:
    push    ebx
    push    esi
    push    edi
    push    ebp
    mov     ebp, esp
    ; [ebp+20]=rdv_server_ip, [ebp+24]=rdv_port, [ebp+28]=device_id

    ;; Build RegisterPeer submessage
    lea     edi, [_rdv_submsg]
    ;; field 1: id (device_id string)
    mov     esi, [ebp+28]
    call    pm_strlen
    mov     ecx, eax
    mov     ebx, 1              ; field number
    call    pb_write_string
    mov     esi, eax            ; bytes written

    ;; field 5: platform
    lea     edi, [_rdv_submsg]
    add     edi, esi
    push    esi
    mov     esi, _rdv_id        ; reuse as platform (will be overwritten)
    ;; Actually, just write "linux" or detect from vtable
    ;; For now, hardcode "linux"
    sub     esp, 8
    mov     dword [esp], 'linu'
    mov     byte [esp+4], 'x'
    mov     byte [esp+5], 0
    mov     esi, esp
    mov     ecx, 5
    mov     ebx, 5              ; field number
    call    pb_write_string
    add     esp, 8
    pop     esi
    add     esi, eax            ; total submsg size

    ;; Wrap in RendezvousMessage envelope (field 6 = RegisterPeer)
    lea     edi, [_rdv_buf]
    mov     ecx, esi            ; submsg size
    mov     ebx, RDV_REGISTER_PEER
    lea     esi, [_rdv_submsg]
    ;; pb_write_string works for submessages too (same encoding)
    call    pb_write_string     ; writes tag + len + submsg bytes
    ;; eax = total bytes in _rdv_buf

    ;; TODO: send via UDP to rdv_server_ip:rdv_port
    ;; This requires socketcall(SC_SOCKET, SOCK_DGRAM) + sendto
    ;; Not implemented yet — needs UDP vtable entries

    pop     ebp
    pop     edi
    pop     esi
    pop     ebx
    ret
