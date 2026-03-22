;; =============================================================================
;; util.inc — String/IO utilities for pmash Linux
;; Part of pmash — lightweight remote agent (Linux port)
;; =============================================================================

section .data
    crlf db 10, 0

section .bss
    _hStdOut resq 1
    _hStdErr resq 1
    _logBuf  resb 512

section .text

;; =============================================================================
;; strlen — Get string length
;; Args: rdi = ASCIIZ string
;; Returns: rax = length
;; =============================================================================
strlen:
    xor     rax, rax
    test    rdi, rdi
    jz      .done
.loop:
    cmp     byte [rdi + rax], 0
    je      .done
    inc     rax
    jmp     .loop
.done:
    ret

;; =============================================================================
;; stdout — Write string to stdout
;; Args: rdi = ASCIIZ string
;; =============================================================================
stdout:
    push    rdi
    call    strlen
    mov     rdx, rax            ; len
    pop     rsi                 ; buf
    mov     rdi, 1              ; fd = stdout
    mov     rax, SYS_WRITE
    syscall
    ret

;; =============================================================================
;; stderr — Write string to stderr
;; Args: rdi = ASCIIZ string
;; =============================================================================
stderr:
    push    rdi
    call    strlen
    mov     rdx, rax
    pop     rsi
    mov     rdi, 2              ; fd = stderr
    mov     rax, SYS_WRITE
    syscall
    ret

;; =============================================================================
;; write_fd — Write buffer to fd
;; Args: rdi = fd, rsi = buf, rdx = len
;; Returns: bytes written in rax
;; =============================================================================
write_fd:
    mov     rax, SYS_WRITE
    syscall
    ret

;; =============================================================================
;; read_fd — Read from fd
;; Args: rdi = fd, rsi = buf, rdx = max len
;; Returns: bytes read in rax
;; =============================================================================
read_fd:
    mov     rax, SYS_READ
    syscall
    ret

;; =============================================================================
;; memcpy — Copy memory
;; Args: rdi = dest, rsi = src, rdx = len
;; =============================================================================
memcpy:
    mov     rcx, rdx
    rep movsb
    ret

;; =============================================================================
;; memset — Fill memory
;; Args: rdi = dest, rsi = byte value, rdx = len
;; =============================================================================
memset:
    mov     rax, rsi
    mov     rcx, rdx
    rep stosb
    ret

;; =============================================================================
;; memcmp — Compare memory
;; Args: rdi = a, rsi = b, rdx = len
;; Returns: 0 if equal, nonzero if different
;; =============================================================================
memcmp:
    mov     rcx, rdx
    repe cmpsb
    jne     .diff
    xor     rax, rax
    ret
.diff:
    mov     rax, 1
    ret

;; =============================================================================
;; atoi — ASCII to integer
;; Args: rdi = string
;; Returns: rax = value
;; =============================================================================
atoi:
    xor     rax, rax
    xor     rcx, rcx            ; sign
    cmp     byte [rdi], '-'
    jne     .loop
    mov     rcx, 1
    inc     rdi
.loop:
    movzx   rdx, byte [rdi]
    cmp     dl, '0'
    jb      .done
    cmp     dl, '9'
    ja      .done
    imul    rax, 10
    sub     dl, '0'
    add     rax, rdx
    inc     rdi
    jmp     .loop
.done:
    test    rcx, rcx
    jz      .ret
    neg     rax
.ret:
    ret

;; =============================================================================
;; itoa — Integer to ASCII (decimal)
;; Args: rdi = value, rsi = output buffer
;; Returns: rax = length
;; =============================================================================
itoa:
    push    rbx
    mov     rax, rdi
    mov     rbx, rsi
    mov     rcx, 0              ; digit count
    mov     r8, 10
    ;; Handle 0
    test    rax, rax
    jnz     .push_digits
    mov     byte [rbx], '0'
    mov     byte [rbx + 1], 0
    mov     rax, 1
    pop     rbx
    ret
.push_digits:
    ;; Push digits onto stack (reverse order)
    xor     rdx, rdx
    div     r8
    add     dl, '0'
    push    rdx
    inc     rcx
    test    rax, rax
    jnz     .push_digits
    ;; Pop digits into buffer
    mov     rax, rcx            ; save length
    mov     rdi, rbx
.pop_digits:
    pop     rdx
    mov     [rdi], dl
    inc     rdi
    dec     rcx
    jnz     .pop_digits
    mov     byte [rdi], 0
    pop     rbx
    ret

;; =============================================================================
;; htons — Host to network byte order (16-bit)
;; Args: di = host value
;; Returns: ax = network value
;; =============================================================================
htons:
    mov     ax, di
    xchg    al, ah
    ret

;; =============================================================================
;; htonl — Host to network byte order (32-bit)
;; Args: edi = host value
;; Returns: eax = network value
;; =============================================================================
htonl:
    mov     eax, edi
    bswap   eax
    ret
