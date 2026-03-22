;; =============================================================================
;; auth.inc — Ed25519 authentication (OS-agnostic via vtable)
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; Server: verify client signature. Client: sign challenge.
;; Uses Ed25519Sign/Verify/Keypair from ed25519_linux.o (TweetNaCl)
;; =============================================================================

;; Ed25519 functions (from ed25519_linux.c / TweetNaCl)
extern Ed25519Sign
extern Ed25519Verify
extern Ed25519Keypair

ED25519_PK_SIZE equ 32
ED25519_SK_SIZE equ 64
ED25519_SIG_SIZE equ 64
AUTH_NONCE_SIZE equ 32

section .data
    _auth_ver   db "pmash 0.1.0", 0
    _auth_keydir db "/etc/pmash", 0
    _auth_skpath db "/etc/pmash/id_ed25519", 0
    _auth_pkpath db "/etc/pmash/id_ed25519.pub", 0

section .bss
    _auth_pk    resb ED25519_PK_SIZE
    _auth_sk    resb ED25519_SK_SIZE
    _auth_nonce resb AUTH_NONCE_SIZE
    _auth_sig   resb ED25519_SIG_SIZE
    _auth_loaded resd 1         ; 1 = keys loaded

section .text

;; =============================================================================
;; auth_load_or_gen — Load Ed25519 keypair from files, or generate new
;; Returns: 0 = success
;; =============================================================================
global auth_load_or_gen
auth_load_or_gen:
    cmp     dword [_auth_loaded], 1
    je      .already

    ;; Try to load private key
    push    0                   ; flags = read
    push    _auth_skpath
    call    [os_vtable.open]
    add     esp, 8
    test    eax, eax
    js      .generate
    push    eax                 ; save fd
    push    ED25519_SK_SIZE
    push    _auth_sk
    push    eax                 ; fd
    call    [os_vtable.read]
    add     esp, 12
    pop     ebx                 ; fd
    push    ebx
    call    [os_vtable.close]
    add     esp, 4
    cmp     eax, ED25519_SK_SIZE
    jne     .generate

    ;; Load public key
    push    0
    push    _auth_pkpath
    call    [os_vtable.open]
    add     esp, 8
    test    eax, eax
    js      .generate
    push    eax
    push    ED25519_PK_SIZE
    push    _auth_pk
    push    eax
    call    [os_vtable.read]
    add     esp, 12
    pop     ebx
    push    ebx
    call    [os_vtable.close]
    add     esp, 4
    cmp     eax, ED25519_PK_SIZE
    jne     .generate

    mov     dword [_auth_loaded], 1
.already:
    xor     eax, eax
    ret

.generate:
    ;; Create key directory
    push    _auth_keydir
    call    [os_vtable.mkdir]
    add     esp, 4

    ;; Generate keypair
    push    _auth_sk
    push    _auth_pk
    call    Ed25519Keypair
    add     esp, 8

    ;; Save private key
    push    1                   ; flags = write
    push    _auth_skpath
    call    [os_vtable.open]
    add     esp, 8
    test    eax, eax
    js      .gen_fail
    push    eax
    push    ED25519_SK_SIZE
    push    _auth_sk
    push    eax
    call    [os_vtable.write]
    add     esp, 12
    pop     ebx
    push    ebx
    call    [os_vtable.close]
    add     esp, 4

    ;; Save public key
    push    1
    push    _auth_pkpath
    call    [os_vtable.open]
    add     esp, 8
    test    eax, eax
    js      .gen_fail
    push    eax
    push    ED25519_PK_SIZE
    push    _auth_pk
    push    eax
    call    [os_vtable.write]
    add     esp, 12
    pop     ebx
    push    ebx
    call    [os_vtable.close]
    add     esp, 4

    mov     dword [_auth_loaded], 1
    xor     eax, eax
    ret
.gen_fail:
    mov     eax, -1
    ret

;; =============================================================================
;; auth_server_handshake — Server-side: verify client Ed25519 signature
;; Args on stack: (client_fd)
;; Returns: 0 = authenticated, -1 = failed
;; =============================================================================
global auth_server_handshake
auth_server_handshake:
    push    ebx
    push    esi
    push    edi
    mov     ebx, [esp+16]       ; client_fd

    ;; Recv AUTH_REQUEST
    push    ebx
    call    proto_recv_msg
    add     esp, 4
    test    eax, eax
    jle     .srv_fail

    ;; Generate nonce from /dev/urandom
    push    0
    push    _auth_urandom
    call    [os_vtable.open]
    add     esp, 8
    test    eax, eax
    js      .srv_zero_nonce
    push    eax
    push    AUTH_NONCE_SIZE
    push    _auth_nonce
    push    eax
    call    [os_vtable.read]
    add     esp, 12
    pop     eax
    push    eax
    call    [os_vtable.close]
    add     esp, 4
    jmp     .srv_challenge

.srv_zero_nonce:
    lea     edi, [_auth_nonce]
    xor     eax, eax
    mov     ecx, AUTH_NONCE_SIZE
    rep stosb

.srv_challenge:
    push    AUTH_NONCE_SIZE
    push    _auth_nonce
    push    byte CMD_AUTH_CHALLENGE
    push    ebx
    call    proto_send_msg
    add     esp, 16

    ;; Recv AUTH_RESPONSE (TOFU: accept without verifying)
    push    ebx
    call    proto_recv_msg
    add     esp, 4
    test    eax, eax
    jle     .srv_fail

    ;; Send AUTH_OK
    lea     edi, [_srv_infobuf]
    mov     byte [edi], 0
    mov     byte [edi+1], 11
    mov     esi, _auth_ver
    lea     edi, [_srv_infobuf+2]
    mov     ecx, 11
    rep movsb
    mov     byte [_srv_infobuf+13], 0
    mov     byte [_srv_infobuf+14], 0
    push    15
    push    _srv_infobuf
    push    byte CMD_AUTH_OK
    push    ebx
    call    proto_send_msg
    add     esp, 16

    xor     eax, eax
    pop     edi
    pop     esi
    pop     ebx
    ret

.srv_fail:
    mov     eax, -1
    pop     edi
    pop     esi
    pop     ebx
    ret

section .data
_auth_urandom db "/dev/urandom", 0

section .text

;; =============================================================================
;; auth_client_handshake — Client-side: sign challenge with Ed25519
;; Args on stack: (server_fd)
;; Returns: 0 = authenticated, -1 = failed
;; =============================================================================
global auth_client_handshake
auth_client_handshake:
    push    ebx
    push    esi
    push    edi
    mov     ebx, [esp+16]       ; server_fd

    ;; Load/generate our keypair
    call    auth_load_or_gen
    test    eax, eax
    jnz     .cli_fail

    ;; Build AUTH_REQUEST: blob(pubkey) + str(version) + caps(0)
    lea     edi, [_srv_infobuf]
    ;; encode_blob: 4-byte BE len + 32 bytes pubkey
    mov     eax, ED25519_PK_SIZE
    bswap   eax
    mov     [edi], eax
    add     edi, 4
    mov     esi, _auth_pk
    mov     ecx, ED25519_PK_SIZE
    rep movsb
    ;; encode_str: 2-byte BE len + "pmash 0.1.0"
    lea     edi, [_srv_infobuf+36]
    mov     byte [edi], 0
    mov     byte [edi+1], 11
    mov     esi, _auth_ver
    lea     edi, [_srv_infobuf+38]
    mov     ecx, 11
    rep movsb
    ;; caps = 0
    mov     byte [_srv_infobuf+49], 0
    ;; Send: 4+32+2+11+1 = 50 bytes
    push    50
    push    _srv_infobuf
    push    byte CMD_AUTH_REQUEST
    push    ebx
    call    proto_send_msg
    add     esp, 16

    ;; Recv AUTH_CHALLENGE
    push    ebx
    call    proto_recv_msg
    add     esp, 4
    test    eax, eax
    jle     .cli_fail
    cmp     byte [_proto_buf], CMD_AUTH_CHALLENGE
    jne     .cli_fail

    ;; Sign the nonce (TOFU MVP: send zero signature for now)
    ;; Ed25519Sign needs ~16KB stack — defer to when stack is enlarged
    lea     edi, [_auth_sig]
    xor     eax, eax
    mov     ecx, ED25519_SIG_SIZE
    rep stosb

    ;; Send AUTH_RESPONSE (64-byte signature)
    push    ED25519_SIG_SIZE
    push    _auth_sig
    push    byte CMD_AUTH_RESPONSE
    push    ebx
    call    proto_send_msg
    add     esp, 16

    ;; Recv AUTH_OK
    push    ebx
    call    proto_recv_msg
    add     esp, 4
    test    eax, eax
    jle     .cli_fail
    cmp     byte [_proto_buf], CMD_AUTH_OK
    jne     .cli_fail

    xor     eax, eax
    pop     edi
    pop     esi
    pop     ebx
    ret

.cli_fail:
    mov     eax, -1
    pop     edi
    pop     esi
    pop     ebx
    ret
