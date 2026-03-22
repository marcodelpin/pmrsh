;; =============================================================================
;; protobuf.inc — Minimal protobuf varint/field encoder (OS-agnostic)
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; Pure math — zero OS calls. Used for hbbs rendezvous protocol.
;; =============================================================================

section .text

;; =============================================================================
;; pb_encode_varint(edi=buf, eax=value) → ecx = bytes written
;; =============================================================================
global pb_encode_varint
pb_encode_varint:
    xor     ecx, ecx
.loop:
    mov     edx, eax
    and     dl, 0x7F
    shr     eax, 7
    test    eax, eax
    jz      .last
    or      dl, 0x80
    mov     [edi+ecx], dl
    inc     ecx
    jmp     .loop
.last:
    mov     [edi+ecx], dl
    inc     ecx
    ret

;; =============================================================================
;; pb_decode_varint(esi=buf) → eax = value, esi advanced past varint
;; =============================================================================
global pb_decode_varint
pb_decode_varint:
    xor     eax, eax
    xor     ecx, ecx            ; shift
.loop:
    movzx   edx, byte [esi]
    inc     esi
    push    edx
    and     edx, 0x7F
    shl     edx, cl
    or      eax, edx
    add     cl, 7
    pop     edx
    test    dl, 0x80
    jnz     .loop
    ret

;; =============================================================================
;; pb_write_string(edi=buf, ebx=field_num, esi=string, ecx=strlen) → eax = bytes written
;; Writes: tag(varint) + len(varint) + string bytes
;; =============================================================================
global pb_write_string
pb_write_string:
    push    ebp
    mov     ebp, edi             ; save start
    test    ecx, ecx
    jz      .zero

    ;; Tag: (field_num << 3) | 2 (length-delimited)
    push    ecx                  ; save strlen
    mov     eax, ebx
    shl     eax, 3
    or      eax, 2
    call    pb_encode_varint
    add     edi, ecx

    ;; Length varint
    pop     eax                  ; strlen
    push    eax
    call    pb_encode_varint
    add     edi, ecx

    ;; Copy string bytes
    pop     ecx                  ; strlen
    push    ecx
    rep movsb
    pop     ecx

    mov     eax, edi
    sub     eax, ebp             ; total bytes written
    pop     ebp
    ret

.zero:
    xor     eax, eax
    pop     ebp
    ret

;; =============================================================================
;; pb_write_int32(edi=buf, ebx=field_num, eax=value) → ecx = bytes written, edi advanced
;; =============================================================================
global pb_write_int32
pb_write_int32:
    push    ebp
    mov     ebp, edi
    test    eax, eax
    jz      .zero

    push    eax                  ; save value
    ;; Tag: (field_num << 3) | 0 (varint)
    mov     eax, ebx
    shl     eax, 3
    call    pb_encode_varint
    add     edi, ecx

    ;; Value varint
    pop     eax
    call    pb_encode_varint
    add     edi, ecx

    mov     eax, edi
    sub     eax, ebp
    mov     ecx, eax
    pop     ebp
    ret
.zero:
    xor     ecx, ecx
    pop     ebp
    ret

;; =============================================================================
;; pb_skip_field(esi=buf, edx=wire_type) → esi advanced past field
;; =============================================================================
global pb_skip_field
pb_skip_field:
    cmp     edx, 0              ; varint
    je      .skip_varint
    cmp     edx, 2              ; length-delimited
    je      .skip_len
    ;; Unknown — can't skip safely
    ret

.skip_varint:
    call    pb_decode_varint     ; consumes varint, advances esi
    ret

.skip_len:
    call    pb_decode_varint     ; eax = length
    add     esi, eax             ; skip data bytes
    ret
