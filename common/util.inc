;; =============================================================================
;; util.inc — String/memory utilities (OS-agnostic)
;; Part of pmash — lightweight remote agent
;; =============================================================================

section .text

;; strlen(esi) → eax
global pm_strlen
pm_strlen:
    xor     eax, eax
    test    esi, esi
    jz      .done
.loop:
    cmp     byte [esi+eax], 0
    je      .done
    inc     eax
    jmp     .loop
.done:
    ret

;; memcpy(edi=dst, esi=src, ecx=len)
global pm_memcpy
pm_memcpy:
    push    ecx
    rep movsb
    pop     ecx
    ret

;; memset(edi=dst, al=byte, ecx=len)
global pm_memset
pm_memset:
    push    ecx
    rep stosb
    pop     ecx
    ret

;; memcmp(esi=a, edi=b, ecx=len) → eax (0=equal)
global pm_memcmp
pm_memcmp:
    repe cmpsb
    jne     .diff
    xor     eax, eax
    ret
.diff:
    mov     eax, 1
    ret

;; atoi(esi=string) → eax
global pm_atoi
pm_atoi:
    xor     eax, eax
    xor     ecx, ecx           ; sign
    cmp     byte [esi], '-'
    jne     .loop
    inc     ecx
    inc     esi
.loop:
    movzx   edx, byte [esi]
    cmp     dl, '0'
    jb      .done
    cmp     dl, '9'
    ja      .done
    imul    eax, 10
    sub     dl, '0'
    movzx   edx, dl
    add     eax, edx
    inc     esi
    jmp     .loop
.done:
    test    ecx, ecx
    jz      .ret
    neg     eax
.ret:
    ret

;; htons(ax) → ax (swap bytes)
global pm_htons
pm_htons:
    xchg    al, ah
    ret

;; htonl(eax) → eax
global pm_htonl
pm_htonl:
    bswap   eax
    ret

;; stdout_str(esi=string) — write ASCIIZ to stdout via vtable
global pm_stdout
pm_stdout:
    push    esi
    call    pm_strlen
    push    eax                 ; len
    push    esi                 ; buf  (esi was preserved before strlen? no, it's arg)
    ;; Actually esi is the arg, strlen uses it
    pop     esi                 ; wrong — let's redo
    pop     eax
    pop     esi                 ; original esi
    ;; Simpler: use vtable
    push    esi
    call    pm_strlen
    mov     edx, eax            ; len
    pop     esi
    push    edx                 ; len
    push    esi                 ; buf
    push    1                   ; fd = stdout
    call    [os_vtable.write]
    add     esp, 12
    ret

;; stderr_str(esi=string) — write ASCIIZ to stderr via vtable
global pm_stderr
pm_stderr:
    push    esi
    call    pm_strlen
    mov     edx, eax
    pop     esi
    push    edx
    push    esi
    push    2                   ; fd = stderr
    call    [os_vtable.write]
    add     esp, 12
    ret

