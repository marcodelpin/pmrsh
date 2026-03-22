;; =============================================================================
;; protobuf.inc — Minimal protobuf varint/field encoder (OS-agnostic, x86_64)
;; Part of pmash — lightweight remote agent
;; =============================================================================

section .text

;; pb_encode_varint(rdi=buf, rsi=value) → rax = bytes written
global pb_encode_varint
pb_encode_varint:
    mov     rax, rsi               ; value
    xor     ecx, ecx               ; bytes written
.loop:
    mov     edx, eax
    and     dl, 0x7F
    shr     rax, 7
    test    rax, rax
    jz      .last
    or      dl, 0x80
    mov     [rdi+rcx], dl
    inc     ecx
    jmp     .loop
.last:
    mov     [rdi+rcx], dl
    inc     ecx
    mov     eax, ecx
    ret

;; pb_decode_varint(rdi=buf) → rax = value, rdx = bytes consumed
global pb_decode_varint
pb_decode_varint:
    xor     eax, eax
    xor     ecx, ecx               ; shift
    xor     r8d, r8d               ; byte index
.loop:
    movzx   edx, byte [rdi+r8]
    inc     r8
    push    rdx
    and     edx, 0x7F
    shl     rdx, cl
    or      rax, rdx
    add     cl, 7
    pop     rdx
    test    dl, 0x80
    jnz     .loop
    mov     rdx, r8                ; bytes consumed
    ret

;; pb_write_string(rdi=buf, rsi=field_num, rdx=string, rcx=strlen) → rax = bytes written
global pb_write_string
pb_write_string:
    push    rbx
    push    r12
    push    r13
    push    r14
    mov     r12, rdi               ; buf start
    mov     r13, rdx               ; string ptr
    mov     r14, rcx               ; string len
    test    rcx, rcx
    jz      .zero

    ;; Tag: (field_num << 3) | 2 (length-delimited)
    mov     rax, rsi
    shl     rax, 3
    or      rax, 2
    mov     rsi, rax
    call    pb_encode_varint       ; rdi=buf, rsi=value → rax=bytes
    add     rdi, rax

    ;; Length varint
    mov     rsi, r14
    call    pb_encode_varint
    add     rdi, rax

    ;; Copy string bytes
    mov     rsi, r13
    mov     rcx, r14
    rep movsb

    mov     rax, rdi
    sub     rax, r12               ; total bytes written
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

.zero:
    xor     eax, eax
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

;; pb_write_int32(rdi=buf, rsi=field_num, rdx=value) → rax = bytes written
global pb_write_int32
pb_write_int32:
    push    rbx
    push    r12
    mov     r12, rdi               ; save buf start
    mov     rbx, rdx               ; save value
    test    rdx, rdx
    jz      .zero

    ;; Tag: (field_num << 3) | 0 (varint)
    mov     rax, rsi
    shl     rax, 3
    mov     rsi, rax
    call    pb_encode_varint
    add     rdi, rax

    ;; Value varint
    mov     rsi, rbx
    call    pb_encode_varint
    add     rdi, rax

    mov     rax, rdi
    sub     rax, r12
    pop     r12
    pop     rbx
    ret
.zero:
    xor     eax, eax
    pop     r12
    pop     rbx
    ret

;; pb_skip_field(rdi=buf, rsi=wire_type) → rax = bytes consumed
global pb_skip_field
pb_skip_field:
    cmp     esi, 0                 ; varint
    je      .skip_varint
    cmp     esi, 2                 ; length-delimited
    je      .skip_len
    xor     eax, eax
    ret

.skip_varint:
    call    pb_decode_varint       ; rdi=buf → rax=value, rdx=bytes consumed
    mov     rax, rdx
    ret

.skip_len:
    call    pb_decode_varint       ; rax=length, rdx=bytes consumed
    add     rax, rdx               ; skip data bytes too
    ret
