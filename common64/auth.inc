;; =============================================================================
;; auth.inc — Ed25519 authentication (OS-agnostic via vtable, x86_64)
;; Part of pmash — lightweight remote agent
;; =============================================================================

;; Ed25519 functions (from ed25519_linux64.c / TweetNaCl)
extern Ed25519Sign
extern Ed25519Verify
extern Ed25519Keypair

ED25519_PK_SIZE equ 32
ED25519_SK_SIZE equ 64
ED25519_SIG_SIZE equ 64
AUTH_NONCE_SIZE equ 32

section .data
    _auth_ver   db "pmash 0.2.0", 0

section .bss
    _auth_keydir_buf resb 128      ; resolved at runtime: $HOME/.pmash
    _auth_skpath_buf resb 160      ; $HOME/.pmash/id_ed25519
    _auth_pkpath_buf resb 160      ; $HOME/.pmash/id_ed25519.pub

section .data
    _auth_keydir_sfx db "/.pmash", 0
    _auth_sk_sfx     db "/.pmash/id_ed25519", 0
    _auth_pk_sfx     db "/.pmash/id_ed25519.pub", 0
    _auth_home_env   db "HOME", 0
    _auth_fallback   db "/tmp", 0

section .bss
    _auth_pk    resb ED25519_PK_SIZE
    _auth_sk    resb ED25519_SK_SIZE
    _auth_nonce resb AUTH_NONCE_SIZE
    _auth_sig   resb ED25519_SIG_SIZE
    _auth_loaded resd 1

section .text

;; =============================================================================
;; auth_load_or_gen — Load Ed25519 keypair from files, or generate new
;; Returns: 0 = success
;; =============================================================================
;; =============================================================================
;; auth_resolve_paths — Build key paths from $HOME (call once at startup)
;; Args: rdi = pointer to envp array (NULL-terminated)
;; =============================================================================
global auth_resolve_paths
auth_resolve_paths:
    push    rbx
    push    r12
    ;; Scan envp for HOME=
    mov     r12, rdi
.env_scan:
    mov     rdi, [r12]
    test    rdi, rdi
    jz      .env_fallback
    ;; Check if starts with "HOME="
    cmp     dword [rdi], 'HOME'
    jne     .env_next
    cmp     byte [rdi+4], '='
    jne     .env_next
    ;; Found HOME= — rdi+5 = home path
    lea     rsi, [rdi+5]
    jmp     .env_build
.env_next:
    add     r12, 8
    jmp     .env_scan
.env_fallback:
    lea     rsi, [_auth_fallback]
.env_build:
    ;; Copy home to keydir_buf + append suffixes
    ;; _auth_keydir_buf = $HOME + "/.pmash"
    lea     rdi, [_auth_keydir_buf]
    mov     rbx, rsi               ; save home ptr
    ;; Copy home
.copy_home1:
    lodsb
    test    al, al
    jz      .home1_done
    stosb
    jmp     .copy_home1
.home1_done:
    ;; Append /.pmash
    lea     rsi, [_auth_keydir_sfx]
.copy_sfx1:
    lodsb
    stosb
    test    al, al
    jnz     .copy_sfx1

    ;; _auth_skpath_buf = $HOME + "/.pmash/id_ed25519"
    lea     rdi, [_auth_skpath_buf]
    mov     rsi, rbx
.copy_home2:
    lodsb
    test    al, al
    jz      .home2_done
    stosb
    jmp     .copy_home2
.home2_done:
    lea     rsi, [_auth_sk_sfx]
.copy_sfx2:
    lodsb
    stosb
    test    al, al
    jnz     .copy_sfx2

    ;; _auth_pkpath_buf = $HOME + "/.pmash/id_ed25519.pub"
    lea     rdi, [_auth_pkpath_buf]
    mov     rsi, rbx
.copy_home3:
    lodsb
    test    al, al
    jz      .home3_done
    stosb
    jmp     .copy_home3
.home3_done:
    lea     rsi, [_auth_pk_sfx]
.copy_sfx3:
    lodsb
    stosb
    test    al, al
    jnz     .copy_sfx3

    pop     r12
    pop     rbx
    ret

global auth_load_or_gen
auth_load_or_gen:
    cmp     dword [_auth_loaded], 1
    je      .already

    push    rbx

    ;; Try to load private key
    lea     rdi, [_auth_skpath_buf]
    xor     esi, esi               ; flags = read
    call    [os_vtable.open]
    test    eax, eax
    js      .generate
    mov     ebx, eax               ; save fd
    mov     edi, eax
    lea     rsi, [_auth_sk]
    mov     edx, ED25519_SK_SIZE
    call    [os_vtable.read]
    push    rax                    ; save bytes read
    mov     edi, ebx
    call    [os_vtable.close]
    pop     rax
    cmp     eax, ED25519_SK_SIZE
    jne     .generate

    ;; Load public key
    lea     rdi, [_auth_pkpath_buf]
    xor     esi, esi
    call    [os_vtable.open]
    test    eax, eax
    js      .generate
    mov     ebx, eax
    mov     edi, eax
    lea     rsi, [_auth_pk]
    mov     edx, ED25519_PK_SIZE
    call    [os_vtable.read]
    push    rax
    mov     edi, ebx
    call    [os_vtable.close]
    pop     rax
    cmp     eax, ED25519_PK_SIZE
    jne     .generate

    mov     dword [_auth_loaded], 1
    pop     rbx
.already:
    xor     eax, eax
    ret

.generate:
    ;; Create key directory
    lea     rdi, [_auth_keydir_buf]
    call    [os_vtable.mkdir]

    ;; Generate keypair
    lea     rdi, [_auth_pk]
    lea     rsi, [_auth_sk]
    call    Ed25519Keypair

    ;; Save private key
    lea     rdi, [_auth_skpath_buf]
    mov     esi, 1                 ; flags = write
    call    [os_vtable.open]
    test    eax, eax
    js      .gen_fail
    mov     ebx, eax
    mov     edi, eax
    lea     rsi, [_auth_sk]
    mov     edx, ED25519_SK_SIZE
    call    [os_vtable.write]
    mov     edi, ebx
    call    [os_vtable.close]

    ;; Save public key
    lea     rdi, [_auth_pkpath_buf]
    mov     esi, 1
    call    [os_vtable.open]
    test    eax, eax
    js      .gen_fail
    mov     ebx, eax
    mov     edi, eax
    lea     rsi, [_auth_pk]
    mov     edx, ED25519_PK_SIZE
    call    [os_vtable.write]
    mov     edi, ebx
    call    [os_vtable.close]

    mov     dword [_auth_loaded], 1
    pop     rbx
    xor     eax, eax
    ret
.gen_fail:
    pop     rbx
    mov     eax, -1
    ret

;; =============================================================================
;; auth_server_handshake(rdi=client_fd) → rax=0/-1
;; =============================================================================
global auth_server_handshake
auth_server_handshake:
    push    rbx
    push    r12
    mov     ebx, edi               ; client_fd

    ;; Recv AUTH_REQUEST
    mov     edi, ebx
    call    proto_recv_msg
    test    eax, eax
    jle     .srv_fail

    ;; Generate nonce from /dev/urandom
    lea     rdi, [_auth_urandom]
    xor     esi, esi
    call    [os_vtable.open]
    test    eax, eax
    js      .srv_zero_nonce
    mov     r12d, eax              ; fd
    mov     edi, eax
    lea     rsi, [_auth_nonce]
    mov     edx, AUTH_NONCE_SIZE
    call    [os_vtable.read]
    mov     edi, r12d
    call    [os_vtable.close]
    jmp     .srv_challenge

.srv_zero_nonce:
    lea     rdi, [_auth_nonce]
    xor     esi, esi
    mov     edx, AUTH_NONCE_SIZE
    call    pm_memset

.srv_challenge:
    mov     edi, ebx
    mov     sil, CMD_AUTH_CHALLENGE
    lea     rdx, [_auth_nonce]
    mov     ecx, AUTH_NONCE_SIZE
    call    proto_send_msg

    ;; Recv AUTH_RESPONSE (TOFU: accept without verifying)
    mov     edi, ebx
    call    proto_recv_msg
    test    eax, eax
    jle     .srv_fail

    ;; Send AUTH_OK: version info
    lea     rdi, [_srv_infobuf]
    mov     byte [rdi], 0
    mov     byte [rdi+1], 11
    lea     rsi, [_auth_ver]
    lea     rdi, [_srv_infobuf+2]
    mov     ecx, 11
    rep movsb
    mov     byte [_srv_infobuf+13], 0
    mov     byte [_srv_infobuf+14], 0

    mov     edi, ebx
    mov     sil, CMD_AUTH_OK
    lea     rdx, [_srv_infobuf]
    mov     ecx, 15
    call    proto_send_msg

    xor     eax, eax
    pop     r12
    pop     rbx
    ret

.srv_fail:
    mov     eax, -1
    pop     r12
    pop     rbx
    ret

section .data
_auth_urandom db "/dev/urandom", 0

section .text

;; =============================================================================
;; auth_client_handshake(rdi=server_fd) → rax=0/-1
;; =============================================================================
global auth_client_handshake
auth_client_handshake:
    push    rbx
    push    r12
    mov     ebx, edi               ; server_fd

    ;; Load/generate keypair
    call    auth_load_or_gen
    test    eax, eax
    jnz     .cli_fail

    ;; Build AUTH_REQUEST: blob(pubkey) + str(version) + caps(0)
    lea     rdi, [_srv_infobuf]
    ;; encode_blob: 4-byte BE len + 32 bytes pubkey
    mov     eax, ED25519_PK_SIZE
    bswap   eax
    mov     [rdi], eax
    add     rdi, 4
    lea     rsi, [_auth_pk]
    mov     ecx, ED25519_PK_SIZE
    rep movsb
    ;; encode_str: 2-byte BE len + "pmash 0.2.0"
    lea     rdi, [_srv_infobuf+36]
    mov     byte [rdi], 0
    mov     byte [rdi+1], 11
    lea     rsi, [_auth_ver]
    lea     rdi, [_srv_infobuf+38]
    mov     ecx, 11
    rep movsb
    ;; caps = 0
    mov     byte [_srv_infobuf+49], 0
    ;; Send: 4+32+2+11+1 = 50 bytes
    mov     edi, ebx
    mov     sil, CMD_AUTH_REQUEST
    lea     rdx, [_srv_infobuf]
    mov     ecx, 50
    call    proto_send_msg

    ;; Recv AUTH_CHALLENGE
    mov     edi, ebx
    call    proto_recv_msg
    test    eax, eax
    jle     .cli_fail
    cmp     byte [_proto_buf], CMD_AUTH_CHALLENGE
    jne     .cli_fail

    ;; Sign the nonce (TOFU: send zero signature for now)
    lea     rdi, [_auth_sig]
    xor     esi, esi
    mov     edx, ED25519_SIG_SIZE
    call    pm_memset

    ;; Send AUTH_RESPONSE (64-byte signature)
    mov     edi, ebx
    mov     sil, CMD_AUTH_RESPONSE
    lea     rdx, [_auth_sig]
    mov     ecx, ED25519_SIG_SIZE
    call    proto_send_msg

    ;; Recv AUTH_OK
    mov     edi, ebx
    call    proto_recv_msg
    test    eax, eax
    jle     .cli_fail
    cmp     byte [_proto_buf], CMD_AUTH_OK
    jne     .cli_fail

    xor     eax, eax
    pop     r12
    pop     rbx
    ret

.cli_fail:
    mov     eax, -1
    pop     r12
    pop     rbx
    ret
