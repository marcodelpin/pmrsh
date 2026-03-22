;; =============================================================================
;; exec.inc — Command execution via fork+execve+pipe
;; Part of pmash — lightweight remote agent (Linux port)
;; =============================================================================

section .data
    sh_path db "/bin/sh", 0
    sh_c    db "-c", 0

section .bss
    _exec_pipe  resq 2          ; pipe fds [read, write]
    _exec_buf   resb 65536      ; output capture buffer

section .text

;; =============================================================================
;; exec_command — Execute shell command, capture output
;; Args: rdi = command string (ASCIIZ)
;; Returns: rax = output length, output in _exec_buf
;;          On error: rax = -1
;; =============================================================================
exec_command:
    push    rbx
    push    r12
    push    r13
    mov     r12, rdi            ; save command string

    ;; Create pipe for stdout capture
    lea     rdi, [_exec_pipe]
    mov     rax, SYS_PIPE
    syscall
    test    rax, rax
    js      .fail

    ;; Fork
    mov     rax, SYS_FORK
    syscall
    test    rax, rax
    js      .close_pipe
    jz      .child

    ;; ---- Parent process ----
    mov     r13, rax            ; child PID

    ;; Close write end of pipe
    mov     rdi, [_exec_pipe + 8]
    mov     rax, SYS_CLOSE
    syscall

    ;; Read output from pipe
    xor     rbx, rbx            ; total bytes read
.read_loop:
    mov     rdi, [_exec_pipe]   ; read end
    lea     rsi, [_exec_buf + rbx]
    mov     rdx, 65536
    sub     rdx, rbx
    jle     .read_done          ; buffer full
    mov     rax, SYS_READ
    syscall
    test    rax, rax
    jle     .read_done
    add     rbx, rax
    jmp     .read_loop

.read_done:
    ;; Close read end
    mov     rdi, [_exec_pipe]
    mov     rax, SYS_CLOSE
    syscall

    ;; Wait for child (SYS_WAIT4)
    mov     rdi, r13            ; pid
    xor     rsi, rsi            ; status ptr (NULL)
    xor     rdx, rdx            ; options
    xor     r10, r10            ; rusage
    mov     rax, SYS_WAIT4
    syscall

    ;; Null-terminate output
    mov     byte [_exec_buf + rbx], 0
    mov     rax, rbx            ; return length
    pop     r13
    pop     r12
    pop     rbx
    ret

    ;; ---- Child process ----
.child:
    ;; Close read end of pipe
    mov     rdi, [_exec_pipe]
    mov     rax, SYS_CLOSE
    syscall

    ;; Redirect stdout+stderr to pipe write end
    mov     rdi, [_exec_pipe + 8]   ; write end fd
    mov     rsi, 1                  ; dup2(pipe_write, STDOUT)
    mov     rax, SYS_DUP2
    syscall
    mov     rdi, [_exec_pipe + 8]
    mov     rsi, 2                  ; dup2(pipe_write, STDERR)
    mov     rax, SYS_DUP2
    syscall

    ;; Close original write end
    mov     rdi, [_exec_pipe + 8]
    mov     rax, SYS_CLOSE
    syscall

    ;; execve("/bin/sh", ["/bin/sh", "-c", command], NULL)
    ;; Build argv on stack
    sub     rsp, 32
    lea     rax, [sh_path]
    mov     [rsp], rax              ; argv[0] = "/bin/sh"
    lea     rax, [sh_c]
    mov     [rsp + 8], rax          ; argv[1] = "-c"
    mov     [rsp + 16], r12         ; argv[2] = command
    mov     qword [rsp + 24], 0     ; argv[3] = NULL

    lea     rdi, [sh_path]          ; filename
    mov     rsi, rsp                ; argv
    xor     rdx, rdx                ; envp = NULL
    mov     rax, SYS_EXECVE
    syscall

    ;; If execve fails, exit child
    sys_exit 127

.close_pipe:
    mov     rdi, [_exec_pipe]
    mov     rax, SYS_CLOSE
    syscall
    mov     rdi, [_exec_pipe + 8]
    mov     rax, SYS_CLOSE
    syscall
.fail:
    mov     rax, -1
    pop     r13
    pop     r12
    pop     rbx
    ret
