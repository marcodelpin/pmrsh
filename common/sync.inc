;; =============================================================================
;; sync.inc — Delta sync: block signatures + delta transfer (OS-agnostic)
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; Block-level delta using Adler32 (weak hash) for block matching.
;; Block size: 4096 bytes. Wire format: M/D/E binary markers.
;; Uses vtable for file I/O.
;; =============================================================================

SYNC_BLOCK_SIZE equ 4096

DELTA_MATCH     equ 'M'     ; 1-byte marker + 4-byte BE block index
DELTA_DATA      equ 'D'     ; 1-byte marker + 4-byte BE data length + raw data
DELTA_END       equ 'E'     ; 1-byte marker (end of delta stream)

CMD_SYNC_REQ    equ 0x90
CMD_SYNC_RESP   equ 0x91

section .bss
    _sync_blockbuf resb SYNC_BLOCK_SIZE
    _sync_sigbuf   resb 65536       ; signatures buffer (8 bytes per: 4 index + 4 adler32)
    _sync_marker   resb 8           ; M/D/E marker + header

section .text

;; =============================================================================
;; sync_compute_sigs — Compute Adler32 block signatures for a file
;; Args on stack: (fd) — file descriptor (already open for reading)
;; Returns: eax = number of blocks, signatures in _sync_sigbuf
;; Each entry: [4:index LE][4:adler32]  = 8 bytes per block
;; =============================================================================
global sync_compute_sigs
sync_compute_sigs:
    push    ebx
    push    esi
    push    edi
    push    ebp
    mov     ebp, [esp+20]       ; fd

    xor     ebx, ebx            ; block index
    lea     edi, [_sync_sigbuf]

.read_block:
    ;; Read SYNC_BLOCK_SIZE bytes
    push    SYNC_BLOCK_SIZE
    push    _sync_blockbuf
    push    ebp
    call    [os_vtable.read]
    add     esp, 12
    test    eax, eax
    jle     .done

    ;; Save bytes read
    push    eax

    ;; Compute Adler32
    mov     esi, _sync_blockbuf
    mov     ecx, eax
    call    adler32

    ;; Store signature: [index][adler32]
    mov     [edi], ebx          ; block index
    mov     [edi+4], eax        ; adler32
    add     edi, 8
    inc     ebx

    pop     eax                 ; bytes read
    cmp     eax, SYNC_BLOCK_SIZE
    jl      .done               ; last block was partial
    jmp     .read_block

.done:
    mov     eax, ebx            ; return block count
    pop     ebp
    pop     edi
    pop     esi
    pop     ebx
    ret

;; =============================================================================
;; sync_send_delta — Compare local file blocks against remote sigs, send M/D/E
;; Args on stack: (client_fd, file_fd, remote_sigs_ptr, remote_sig_count)
;; Remote sigs format: [4:index][4:adler32] per entry
;; Sends CMD_SYNC_RESP messages with M/D/E markers
;; =============================================================================
global sync_send_delta
sync_send_delta:
    push    ebx
    push    esi
    push    edi
    push    ebp
    mov     ebp, esp
    ; [ebp+20]=client_fd, [ebp+24]=file_fd, [ebp+28]=sigs_ptr, [ebp+32]=sig_count

.delta_loop:
    ;; Read a block from file
    push    SYNC_BLOCK_SIZE
    push    _sync_blockbuf
    push    dword [ebp+24]      ; file_fd
    call    [os_vtable.read]
    add     esp, 12
    test    eax, eax
    jle     .delta_end

    push    eax                 ; save bytes read

    ;; Compute Adler32 for this block
    mov     esi, _sync_blockbuf
    mov     ecx, eax
    call    adler32
    mov     edx, eax            ; edx = this block's adler32

    ;; Search remote sigs for a match
    mov     esi, [ebp+28]       ; remote sigs ptr
    mov     ecx, [ebp+32]       ; sig count
    xor     edi, edi            ; search index
.search:
    cmp     edi, ecx
    jge     .no_match
    cmp     [esi+4], edx        ; compare adler32
    je      .match
    add     esi, 8              ; next sig entry
    inc     edi
    jmp     .search

.match:
    pop     eax                 ; discard bytes read
    ;; Send M marker: [M][u32be(remote_block_index)]
    mov     byte [_sync_marker], DELTA_MATCH
    mov     eax, [esi]          ; remote block index
    bswap   eax
    mov     [_sync_marker+1], eax
    push    5
    push    _sync_marker
    push    byte CMD_SYNC_RESP
    push    dword [ebp+20]
    call    proto_send_msg
    add     esp, 16
    jmp     .delta_loop

.no_match:
    pop     ecx                 ; bytes read
    ;; Send D marker: [D][u32be(data_len)][data]
    ;; Build in _sync_marker + _sync_blockbuf (already there)
    mov     byte [_sync_marker], DELTA_DATA
    mov     eax, ecx
    bswap   eax
    mov     [_sync_marker+1], eax

    ;; Need to send marker(5) + data(ecx) as one proto message
    ;; proto_send_msg copies to _proto_buf, so we need a combined buffer
    ;; Use _sync_sigbuf temporarily (it's not being read anymore at this point? No, sigs are there)
    ;; Simpler: send two proto messages — marker then data
    ;; Actually, M/D/E should be inside the CMD_SYNC_RESP payload
    ;; So payload = [D][len_BE][data]
    ;; Total payload = 5 + data_len
    push    ecx                 ; save data_len
    add     ecx, 5
    push    ecx                 ; total payload
    ;; We need a buffer with [D][len][data] — _sync_marker has the header (5 bytes)
    ;; and _sync_blockbuf has the data. proto_send_msg copies to _proto_buf anyway.
    ;; But proto_send_msg takes (fd, cmdId, payload_ptr, payload_len) and copies
    ;; payload to _proto_buf[1..]. We need contiguous memory.
    ;; Build it: copy marker(5) + blockbuf(data_len) to _srv_filebuf
    lea     edi, [_srv_filebuf]
    mov     esi, _sync_marker
    push    ecx
    mov     ecx, 5
    rep movsb
    pop     ecx
    pop     edx                 ; total payload (5+data_len)
    pop     eax                 ; data_len
    push    edx                 ; save total again
    mov     esi, _sync_blockbuf
    mov     ecx, eax
    rep movsb

    pop     ecx                 ; total payload size
    push    ecx
    push    _srv_filebuf
    push    byte CMD_SYNC_RESP
    push    dword [ebp+20]
    call    proto_send_msg
    add     esp, 16
    jmp     .delta_loop

.delta_end:
    ;; Send E marker
    mov     byte [_sync_marker], DELTA_END
    push    1
    push    _sync_marker
    push    byte CMD_SYNC_RESP
    push    dword [ebp+20]
    call    proto_send_msg
    add     esp, 16

    pop     ebp
    pop     edi
    pop     esi
    pop     ebx
    ret
