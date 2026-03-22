;; =============================================================================
;; sync.inc — Delta sync (OS-agnostic via vtable, x86_64)
;; Part of pmash — lightweight remote agent
;; =============================================================================

SYNC_BLOCK_SIZE equ 4096
DELTA_MATCH     equ 'M'
DELTA_DATA      equ 'D'
DELTA_END       equ 'E'

CMD_SYNC_REQ      equ 0x90
CMD_SYNC_RESP     equ 0x91
CMD_SYNC_PUSH_REQ equ 0x92   ; client→server: "I want to push delta for <path>"
CMD_SYNC_PUSH_SIGS equ 0x93  ; server→client: here are my block sigs
CMD_SYNC_PUSH_DATA equ 0x94  ; client→server: M/D/E delta stream
CMD_SYNC_PUSH_OK  equ 0x95   ; server→client: push applied

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

;; =============================================================================
;; sync_apply_delta — Client-side: receive M/D/E stream, reconstruct file
;; Args: rdi=server_fd, rsi=local_read_fd, rdx=output_fd
;; local_read_fd = original file open for reading (for M blocks)
;; output_fd = new file open for writing
;; Receives CMD_SYNC_RESP messages until E marker.
;; Returns: rax = 0 success, -1 error
;; =============================================================================
global sync_apply_delta
sync_apply_delta:
    push    rbx
    push    r12
    push    r13
    push    r14
    mov     r12d, edi              ; server_fd
    mov     r13d, esi              ; local_read_fd
    mov     r14d, edx              ; output_fd

.apply_loop:
    ;; Receive next CMD_SYNC_RESP
    mov     edi, r12d
    call    proto_recv_msg
    test    eax, eax
    jle     .apply_err

    ;; Check cmdId
    cmp     byte [_proto_buf], CMD_SYNC_RESP
    jne     .apply_err

    ;; Parse marker (first byte after cmdId)
    movzx   eax, byte [_proto_buf+1]

    cmp     al, DELTA_END
    je      .apply_done

    cmp     al, DELTA_MATCH
    je      .apply_match

    cmp     al, DELTA_DATA
    je      .apply_data

    ;; Unknown marker — skip
    jmp     .apply_loop

.apply_match:
    ;; M + u32be(block_index)
    ;; Seek to block_index * SYNC_BLOCK_SIZE in local file, read block, write to output
    mov     eax, [_proto_buf+2]
    bswap   eax                    ; block index
    imul    eax, SYNC_BLOCK_SIZE   ; byte offset
    ;; Seek local file
    mov     edi, r13d
    mov     esi, eax               ; offset
    xor     edx, edx               ; SEEK_SET = 0
    call    [os_vtable.seek]
    ;; Read block from local file
    mov     edi, r13d
    lea     rsi, [_sync_blockbuf]
    mov     edx, SYNC_BLOCK_SIZE
    call    [os_vtable.read]
    test    eax, eax
    jle     .apply_err
    ;; Write block to output
    mov     edi, r14d
    lea     rsi, [_sync_blockbuf]
    mov     edx, eax
    call    [os_vtable.write]
    jmp     .apply_loop

.apply_data:
    ;; D + u32be(data_len) + raw data
    mov     eax, [_proto_buf+2]
    bswap   eax                    ; data length
    test    eax, eax
    jle     .apply_loop
    ;; Write raw data to output (data starts at _proto_buf+6)
    mov     edi, r14d
    lea     rsi, [_proto_buf+6]
    mov     edx, eax
    call    [os_vtable.write]
    jmp     .apply_loop

.apply_done:
    xor     eax, eax
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

.apply_err:
    mov     eax, -1
    pop     r14
    pop     r13
    pop     r12
    pop     rbx
    ret

;; =============================================================================
;; sync_handle_push — Server-side: receive client's delta M/D/E, reconstruct
;; Args: rdi=client_fd, rsi=local_read_fd, rdx=output_fd
;; Mirror of sync_apply_delta but on server side for sync-push
;; =============================================================================
global sync_handle_push
sync_handle_push:
    ;; Same logic as sync_apply_delta — reuse
    jmp     sync_apply_delta
