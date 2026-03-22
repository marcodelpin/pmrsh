;; =============================================================================
;; relay.inc — Rendezvous DeviceID resolution (OS-agnostic, x86_64)
;; Part of pmash — lightweight remote agent
;; =============================================================================

RDV_REGISTER_PEER equ 6
RDV_PUNCH_HOLE_REQUEST equ 8
RDV_PORT equ 21116

section .data
    _rdv_id     db "pmash-client", 0
    _rdv_ver    db "1.2.7", 0

section .bss
    _rdv_buf    resb 4096
    _rdv_submsg resb 1024

section .text

;; relay_resolve — stub (server doesn't resolve DeviceIDs)
global relay_resolve
relay_resolve:
    mov     eax, -1
    ret

;; relay_register(rdi=rdv_server_ip, rsi=rdv_port, rdx=device_id)
global relay_register
relay_register:
    ;; TODO: build RegisterPeer protobuf + send via UDP
    ;; Stub for now
    xor     eax, eax
    ret
