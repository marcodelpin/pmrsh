;; =============================================================================
;; sync.inc — Delta sync (OS-agnostic via vtable, x86_64)
;; Part of pmash — lightweight remote agent
;; =============================================================================

SYNC_BLOCK_SIZE equ 4096
DELTA_MATCH     equ 'M'
DELTA_DATA      equ 'D'
DELTA_END       equ 'E'

CMD_SYNC_REQ    equ 0x90
CMD_SYNC_RESP   equ 0x91

section .bss
    _sync_blockbuf resb SYNC_BLOCK_SIZE
    _sync_sigbuf   resb 65536
    _sync_marker   resb 8

section .text

;; sync_compute_sigs(rdi=fd) → eax = block_count, sigs in _sync_sigbuf
global sync_compute_sigs
sync_compute_sigs:
    push    rbx
    push    r12
    push    r13
    mov     r12d, edi              ; fd
    xor     ebx, ebx              ; block index
    lea     r13, [_sync_sigbuf]

.read_block:
    mov     edi, r12d
    lea     rsi, [_sync_blockbuf]
    mov     edx, SYNC_BLOCK_SIZE
    call    [os_vtable.read]
    test    eax, eax
    jle     .done
    push    rax                    ; save bytes read

    ;; Compute Adler32
    lea     rdi, [_sync_blockbuf]
    mov     rsi, rax               ; len
    call    adler32

    ;; Store signature: [index][adler32]
    mov     [r13], ebx             ; block index
    mov     [r13+4], eax           ; adler32
    add     r13, 8
    inc     ebx

    pop     rax
    cmp     eax, SYNC_BLOCK_SIZE
    jl      .done
    jmp     .read_block

.done:
    mov     eax, ebx
    pop     r13
    pop     r12
    pop     rbx
    ret

;; sync_send_delta(rdi=client_fd, rsi=file_fd, rdx=sigs_ptr, rcx=sig_count)
global sync_send_delta
sync_send_delta:
    push    rbx
    push    r12
    push    r13
    push    r14
    push    r15
    mov     r12d, edi              ; client_fd
    mov     r13d, esi              ; file_fd
    mov     r14, rdx               ; sigs_ptr
    mov     r15d, ecx              ; sig_count

.delta_loop:
    mov     edi, r13d
    lea     rsi, [_sync_blockbuf]
    mov     edx, SYNC_BLOCK_SIZE
    call    [os_vtable.read]
    test    eax, eax
    jle     .delta_end
    push    rax                    ; save bytes read

    ;; Compute Adler32
    lea     rdi, [_sync_blockbuf]
    mov     rsi, rax
    call    adler32
    mov     ebx, eax               ; this block's adler32

    ;; Search remote sigs
    mov     rsi, r14               ; sigs ptr
    xor     ecx, ecx              ; search index
.search:
    cmp     ecx, r15d
    jge     .no_match
    cmp     [rsi+4], ebx
    je      .match
    add     rsi, 8
    inc     ecx
    jmp     .search

.match:
    pop     rax                    ; discard bytes read
    ;; Send M marker: [M][u32be(block_index)]
    mov     byte [_sync_marker], DELTA_MATCH
    mov     eax, [rsi]             ; remote block index
    bswap   eax
    mov     [_sync_marker+1], eax
    mov     edi, r12d
    mov     sil, CMD_SYNC_RESP
    lea     rdx, [_sync_marker]
    mov     ecx, 5
    call    proto_send_msg
    jmp     .delta_loop

.no_match:
    pop     rcx                    ; bytes read
    ;; Send D marker in _srv_filebuf
    mov     byte [_sync_marker], DELTA_DATA
    mov     eax, ecx
    bswap   eax
    mov     [_sync_marker+1], eax
    ;; Build contiguous buffer in _srv_filebuf
    push    rcx
    lea     rdi, [_srv_filebuf]
    lea     rsi, [_sync_marker]
    push    rcx
    mov     ecx, 5
    rep movsb
    pop     rcx
    lea     rsi, [_sync_blockbuf]
    rep movsb
    pop     rcx
    add     ecx, 5                 ; total payload
    mov     edi, r12d
    mov     sil, CMD_SYNC_RESP
    lea     rdx, [_srv_filebuf]
    call    proto_send_msg
    jmp     .delta_loop

.delta_end:
    mov     byte [_sync_marker], DELTA_END
    mov     edi, r12d
    mov     sil, CMD_SYNC_RESP
    lea     rdx, [_sync_marker]
    mov     ecx, 1
    call    proto_send_msg

    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret
