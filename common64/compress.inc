;; =============================================================================
;; compress.inc — Simple RLE compression (OS-agnostic, x86_64)
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; Simple run-length encoding for wire transfer optimization.
;; Format: [0x00-0x7F] = literal run (len+1 bytes follow)
;;         [0x80-0xFF] = repeat run (len-0x7F repetitions of next byte)
;; Windows uses LZNT1 via ntdll — this is a portable alternative.
;; =============================================================================

CMD_COMPRESS equ 0xE0

section .text

;; =============================================================================
;; rle_compress(rdi=input, rsi=input_len, rdx=output) → rax = output_len
;; =============================================================================
global rle_compress
rle_compress:
    push    rbx
    push    r12
    push    r13
    mov     r12, rdi               ; input
    mov     r13, rdx               ; output
    mov     rcx, rsi               ; remaining
    xor     ebx, ebx               ; output index

    test    rcx, rcx
    jz      .comp_done

.comp_loop:
    cmp     rcx, 0
    jle     .comp_done

    ;; Check for repeat run (3+ identical bytes)
    movzx   eax, byte [r12]
    cmp     rcx, 3
    jl      .comp_literal
    cmp     al, [r12+1]
    jne     .comp_literal
    cmp     al, [r12+2]
    jne     .comp_literal

    ;; Count repeat run (max 128)
    mov     edx, 1
.rep_count:
    cmp     rdx, rcx
    jge     .rep_emit
    cmp     edx, 128
    jge     .rep_emit
    cmp     al, [r12+rdx]
    jne     .rep_emit
    inc     edx
    jmp     .rep_count
.rep_emit:
    ;; Emit: [0x80 + (count-1)] [byte]
    lea     eax, [edx + 0x7F]
    mov     [r13+rbx], al
    inc     ebx
    mov     al, [r12]
    mov     [r13+rbx], al
    inc     ebx
    add     r12, rdx
    sub     rcx, rdx
    jmp     .comp_loop

.comp_literal:
    ;; Scan for literal run (max 128 bytes, until repeat found)
    mov     edx, 0
.lit_count:
    cmp     rdx, rcx
    jge     .lit_emit
    cmp     edx, 128
    jge     .lit_emit
    ;; Check if next 3 bytes are same (start repeat)
    lea     eax, [edx+2]
    cmp     rax, rcx
    jge     .lit_no_rep
    movzx   eax, byte [r12+rdx]
    cmp     al, [r12+rdx+1]
    jne     .lit_no_rep
    cmp     al, [r12+rdx+2]
    jne     .lit_no_rep
    ;; Found repeat — stop literal here
    test    edx, edx
    jz      .lit_no_rep            ; at least 1 literal byte
    jmp     .lit_emit
.lit_no_rep:
    inc     edx
    jmp     .lit_count
.lit_emit:
    test    edx, edx
    jz      .comp_done
    ;; Emit: [count-1] [bytes...]
    lea     eax, [edx-1]
    mov     [r13+rbx], al
    inc     ebx
    ;; Copy literal bytes
    push    rcx
    mov     ecx, edx
.lit_copy:
    mov     al, [r12]
    mov     [r13+rbx], al
    inc     r12
    inc     ebx
    dec     ecx
    jnz     .lit_copy
    pop     rcx
    sub     rcx, rdx
    jmp     .comp_loop

.comp_done:
    mov     eax, ebx
    pop     r13
    pop     r12
    pop     rbx
    ret

;; =============================================================================
;; rle_decompress(rdi=input, rsi=input_len, rdx=output) → rax = output_len
;; =============================================================================
global rle_decompress
rle_decompress:
    push    rbx
    push    r12
    push    r13
    mov     r12, rdi               ; input
    mov     r13, rdx               ; output
    mov     rcx, rsi               ; remaining input
    xor     ebx, ebx               ; output index

.decomp_loop:
    cmp     rcx, 0
    jle     .decomp_done
    movzx   eax, byte [r12]
    inc     r12
    dec     rcx
    test    al, 0x80
    jnz     .decomp_repeat

    ;; Literal run: count = al+1
    inc     eax
    mov     edx, eax
.decomp_lit:
    cmp     rcx, 0
    jle     .decomp_done
    mov     al, [r12]
    mov     [r13+rbx], al
    inc     r12
    inc     ebx
    dec     rcx
    dec     edx
    jnz     .decomp_lit
    jmp     .decomp_loop

.decomp_repeat:
    ;; Repeat run: count = al - 0x7F
    sub     eax, 0x7F
    mov     edx, eax
    cmp     rcx, 0
    jle     .decomp_done
    movzx   eax, byte [r12]
    inc     r12
    dec     rcx
.decomp_rep:
    mov     [r13+rbx], al
    inc     ebx
    dec     edx
    jnz     .decomp_rep
    jmp     .decomp_loop

.decomp_done:
    mov     eax, ebx
    pop     r13
    pop     r12
    pop     rbx
    ret
