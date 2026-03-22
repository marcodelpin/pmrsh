;; =============================================================================
;; shell.inc — Interactive shell via bidirectional pipes
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; Server: creates cmd.exe with redirected stdin/stdout, reader thread
;; Client: sends keystrokes, receives output
;; Protocol: CMD_SHELL_DATA for I/O in both directions
;; =============================================================================

CreatePipe          PROTO :DWORD, :DWORD, :DWORD, :DWORD
CreateProcessA      PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, \
                          :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
CreateThread        PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
PeekNamedPipe       PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
Sleep               PROTO :DWORD

SHELL_BUF_SIZE      equ 4096

.data
    _szShellCmd     db "cmd.exe", 0

.data?
    _shellReadPipe  DWORD ?     ; stdout read end
    _shellWritePipe DWORD ?     ; stdin write end
    _shellProc      DWORD ?     ; process handle
    _shellTls       DWORD ?     ; ptr to TLS context (for reader thread)
    _shellBuf       BYTE SHELL_BUF_SIZE dup(?)
    _shellDwWr      DWORD ?

.code

;; =============================================================================
;; _ShellReaderThread — Reads process stdout, sends CMD_SHELL_DATA to client
;; Runs in background thread. Exits when pipe closes (process exits).
;; =============================================================================
_ShellReaderThread PROC lpParam:DWORD
    LOCAL   dwRead:DWORD
    LOCAL   dwAvail:DWORD

@srt_loop:
    ;; Check if data available (non-blocking)
    invoke  PeekNamedPipe, _shellReadPipe, 0, 0, 0, ADDR dwAvail, 0
    test    eax, eax
    jz      @srt_exit           ; pipe broken = process exited
    cmp     dwAvail, 0
    je      @srt_wait

    ;; Read available data (cap at buffer size)
    mov     eax, dwAvail
    cmp     eax, SHELL_BUF_SIZE
    jle     @srt_read
    mov     eax, SHELL_BUF_SIZE
@srt_read:
    mov     dwAvail, eax        ; reuse local as read size
    invoke  ReadFile, _shellReadPipe, ADDR _shellBuf, dwAvail, ADDR dwRead, 0
    test    eax, eax
    jz      @srt_exit
    cmp     dwRead, 0
    je      @srt_wait

    ;; Send output to client
    invoke  ProtoSendMsg, _shellTls, CMD_SHELL_DATA, ADDR _shellBuf, dwRead
    test    eax, eax
    jnz     @srt_exit
    jmp     @srt_loop

@srt_wait:
    invoke  Sleep, 50           ; poll interval
    jmp     @srt_loop

@srt_exit:
    ret
_ShellReaderThread ENDP

;; =============================================================================
;; ShellHandleServer — Server-side shell session
;; Args: pTlsCtx (TLS context)
;; Creates cmd.exe, pipes I/O bidirectionally until client disconnects.
;; Returns: 0
;; =============================================================================
ShellHandleServer PROC uses ebx esi edi pTlsCtx:DWORD
    LOCAL   hStdinRead:DWORD
    LOCAL   hStdinWrite:DWORD
    LOCAL   hStdoutRead:DWORD
    LOCAL   hStdoutWrite:DWORD
    LOCAL   sa:SECURITY_ATTRIBUTES
    LOCAL   sui:STARTUPINFOA
    LOCAL   pi:PROCESS_INFORMATION
    LOCAL   msg:MRSH_MSG
    LOCAL   hThread:DWORD

    ;; Setup security attributes for pipe inheritance
    mov     sa.nLength, SIZEOF SECURITY_ATTRIBUTES
    mov     sa.lpSecurityDescriptor, 0
    mov     sa.bInheritHandle, TRUE

    ;; Create stdin pipe
    invoke  CreatePipe, ADDR hStdinRead, ADDR hStdinWrite, ADDR sa, 0
    test    eax, eax
    jz      @shs_fail
    ;; Don't inherit the write end of stdin
    invoke  SetHandleInformation, hStdinWrite, HANDLE_FLAG_INHERIT, 0

    ;; Create stdout pipe
    invoke  CreatePipe, ADDR hStdoutRead, ADDR hStdoutWrite, ADDR sa, 0
    test    eax, eax
    jz      @shs_close_stdin
    ;; Don't inherit the read end of stdout
    invoke  SetHandleInformation, hStdoutRead, HANDLE_FLAG_INHERIT, 0

    ;; Setup STARTUPINFO
    invoke  RtlZeroMemory, ADDR sui, SIZEOF STARTUPINFOA
    mov     sui.cb, SIZEOF STARTUPINFOA
    mov     sui.dwFlags, STARTF_USESTDHANDLES or STARTF_USESHOWWINDOW
    mov     sui.wShowWindow, SW_HIDE
    mov     eax, hStdinRead
    mov     sui._hStdIn, eax
    mov     eax, hStdoutWrite
    mov     sui._hStdOut, eax
    mov     sui._hStdErr, eax

    ;; Create cmd.exe process
    invoke  CreateProcessA, 0, ADDR _szShellCmd, 0, 0, TRUE, \
            CREATE_NO_WINDOW, 0, 0, ADDR sui, ADDR pi
    test    eax, eax
    jz      @shs_close_stdout

    ;; Save handles for reader thread
    mov     eax, hStdoutRead
    mov     _shellReadPipe, eax
    mov     eax, hStdinWrite
    mov     _shellWritePipe, eax
    mov     eax, pi.hProcess
    mov     _shellProc, eax
    mov     eax, pTlsCtx
    mov     _shellTls, eax

    ;; Close pipe ends we don't need
    invoke  CloseHandle, hStdinRead
    invoke  CloseHandle, hStdoutWrite

    ;; Start reader thread (reads process stdout → sends to client)
    invoke  CreateThread, 0, 0, ADDR _ShellReaderThread, 0, 0, 0
    mov     hThread, eax

    ;; Main loop: receive client input → write to process stdin
@shs_input:
    invoke  ProtoRecvMsg, pTlsCtx, ADDR msg
    test    eax, eax
    jnz     @shs_done           ; client disconnected
    movzx   eax, msg.cmdId
    cmp     al, CMD_SHELL_DATA
    jne     @shs_chk_end
    ;; Write input to process stdin
    invoke  WriteFile, _shellWritePipe, msg.pData, msg.dataLen, ADDR _shellDwWr, 0
    invoke  ProtoFreeMsg, ADDR msg
    jmp     @shs_input
@shs_chk_end:
    invoke  ProtoFreeMsg, ADDR msg
    ;; Any non-DATA message ends the shell
    jmp     @shs_done

@shs_done:
    ;; Kill process and cleanup
    ;; Order: kill process → wait reader thread (pipe break exits it) → close pipes
    invoke  TerminateProcess, _shellProc, 0
    invoke  WaitForSingleObject, _shellProc, 3000
    invoke  CloseHandle, _shellProc
    invoke  CloseHandle, pi.hThread
    ;; Wait for reader thread BEFORE closing pipes (reader may still be reading)
    invoke  WaitForSingleObject, hThread, 3000
    invoke  CloseHandle, hThread
    invoke  CloseHandle, _shellWritePipe
    invoke  CloseHandle, _shellReadPipe
    xor     eax, eax
    ret

@shs_close_stdout:
    invoke  CloseHandle, hStdoutRead
    invoke  CloseHandle, hStdoutWrite
@shs_close_stdin:
    invoke  CloseHandle, hStdinRead
    invoke  CloseHandle, hStdinWrite
@shs_fail:
    mov     eax, -1
    ret
ShellHandleServer ENDP
