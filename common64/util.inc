;; =============================================================================
;; util.inc — String/memory utilities (OS-agnostic, x86_64)
;; Part of pmash — lightweight remote agent
;; =============================================================================

section .text

;; strlen(rdi=str) → rax=len
global pm_strlen
pm_strlen:
    xor     eax, eax
    test    rdi, rdi
    jz      .done
.loop:
    cmp     byte [rdi+rax], 0
    je      .done
    inc     eax
    jmp     .loop
.done:
    ret

;; memcpy(rdi=dst, rsi=src, rdx=len)
global pm_memcpy
pm_memcpy:
    mov     rcx, rdx
    rep movsb
    ret

;; memset(rdi=dst, rsi=byte, rdx=len)
global pm_memset
pm_memset:
    mov     rcx, rdx
    mov     rax, rsi
    rep stosb
    ret

;; memcmp(rdi=a, rsi=b, rdx=len) → rax (0=equal)
global pm_memcmp
pm_memcmp:
    mov     rcx, rdx
    repe cmpsb
    jne     .diff
    xor     eax, eax
    ret
.diff:
    mov     eax, 1
    ret

;; atoi(rdi=string) → rax
global pm_atoi
pm_atoi:
    xor     eax, eax
    xor     ecx, ecx              ; sign
    mov     rsi, rdi
    cmp     byte [rsi], '-'
    jne     .loop
    inc     ecx
    inc     rsi
.loop:
    movzx   edx, byte [rsi]
    cmp     dl, '0'
    jb      .done
    cmp     dl, '9'
    ja      .done
    imul    rax, 10
    sub     dl, '0'
    movzx   edx, dl
    add     rax, rdx
    inc     rsi
    jmp     .loop
.done:
    test    ecx, ecx
    jz      .ret
    neg     rax
.ret:
    ret

;; htons(di) → ax (swap bytes of 16-bit value)
global pm_htons
pm_htons:
    mov     eax, edi
    xchg    al, ah
    ret

;; htonl(edi) → eax
global pm_htonl
pm_htonl:
    mov     eax, edi
    bswap   eax
    ret

;; stdout_str(rdi=string) — write ASCIIZ to stdout via vtable
global pm_stdout
pm_stdout:
    push    rbx
    mov     rbx, rdi               ; save string ptr
    call    pm_strlen              ; rdi already set
    mov     rdx, rax               ; len
    mov     rsi, rbx               ; buf
    mov     edi, 1                 ; fd = stdout
    call    [os_vtable.write]
    pop     rbx
    ret

;; stderr_str(rdi=string) — write ASCIIZ to stderr via vtable
global pm_stderr
pm_stderr:
    push    rbx
    mov     rbx, rdi
    call    pm_strlen
    mov     rdx, rax
    mov     rsi, rbx
    mov     edi, 2                 ; fd = stderr
    call    [os_vtable.write]
    pop     rbx
    ret
