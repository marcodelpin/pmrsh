;; =============================================================================
;; exec.inc — Remote command execution via CreateProcess
;; Part of pmash — lightweight remote agent
;; =============================================================================

;; ---- Constants ----
STARTF_USESTDHANDLES    equ 00000100h
STARTF_USESHOWWINDOW   equ 00000001h
SW_HIDE                 equ 0
CREATE_NO_WINDOW        equ 08000000h
HANDLE_FLAG_INHERIT     equ 00000001h
INFINITE                equ 0FFFFFFFFh
EXEC_TIMEOUT            equ 30000
WAIT_TIMEOUT            equ 00000102h
GMEM_MOVEABLE           equ 00000002h

IFNDEF NULL
NULL equ 0
ENDIF
IFNDEF TRUE
TRUE equ 1
ENDIF

;; ---- Structures ----
SECURITY_ATTRIBUTES STRUCT
    nLength             DWORD ?
    lpSecurityDescriptor DWORD ?
    bInheritHandle      DWORD ?
SECURITY_ATTRIBUTES ENDS

;; STARTUPINFOA — use _hStd* to avoid MASM name conflicts
STARTUPINFOA STRUCT
    cb              DWORD ?
    lpReserved      DWORD ?
    lpDesktop       DWORD ?
    lpTitle         DWORD ?
    dwX             DWORD ?
    dwY             DWORD ?
    dwXSize         DWORD ?
    dwYSize         DWORD ?
    dwXCountChars   DWORD ?
    dwYCountChars   DWORD ?
    dwFillAttribute DWORD ?
    dwFlags         DWORD ?
    wShowWindow     WORD  ?
    cbReserved2     WORD  ?
    lpReserved2     DWORD ?
    _hStdIn         DWORD ?
    _hStdOut        DWORD ?
    _hStdErr        DWORD ?
STARTUPINFOA ENDS

PROCESS_INFORMATION STRUCT
    hProcess    DWORD ?
    hThread     DWORD ?
    dwProcessId DWORD ?
    dwThreadId  DWORD ?
PROCESS_INFORMATION ENDS

;; ---- API Prototypes ----
CreatePipe              PROTO :DWORD, :DWORD, :DWORD, :DWORD
CreateProcessA          PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, \
                              :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
WaitForSingleObject     PROTO :DWORD, :DWORD
GetExitCodeProcess      PROTO :DWORD, :DWORD
TerminateProcess        PROTO :DWORD, :DWORD
SetHandleInformation    PROTO :DWORD, :DWORD, :DWORD
GlobalReAlloc           PROTO :DWORD, :DWORD, :DWORD
IFNDEF _GLOBALALLOC_DEFINED
_GLOBALALLOC_DEFINED equ 1
GlobalAlloc         PROTO :DWORD, :DWORD
GlobalFree          PROTO :DWORD
ENDIF
CloseHandle         PROTO :DWORD
ReadFile            PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
IFNDEF _RTLZEROMEMORY_DEFINED
_RTLZEROMEMORY_DEFINED equ 1
RtlZeroMemory       PROTO :DWORD, :DWORD
ENDIF
IFNDEF _RTLCOPYMEMORY_DEFINED
_RTLCOPYMEMORY_DEFINED equ 1
RtlMoveMemory       PROTO :DWORD, :DWORD, :DWORD
ENDIF
lstrlenA            PROTO :DWORD
lstrcpyA            PROTO :DWORD, :DWORD
wsprintfA           PROTO C :DWORD, :DWORD, :VARARG

.data
    szPSCmd db "pwsh.exe -NoProfile -Command ", 0

.code

;; =============================================================================
;; ExecCommand — Execute PowerShell command, capture stdout+stderr
;; Returns: 0 = success, -1 = error. Caller GlobalFree's ppOutput.
;; =============================================================================
ExecCommand PROC uses ebx esi edi \
    lpCommand:DWORD, ppOutput:DWORD, pOutputLen:DWORD, pExitCode:DWORD

    LOCAL   hReadPipe:DWORD
    LOCAL   hWritePipe:DWORD
    LOCAL   sa:SECURITY_ATTRIBUTES
    LOCAL   sui:STARTUPINFOA
    LOCAL   pi:PROCESS_INFORMATION
    LOCAL   pCmdLine:DWORD
    LOCAL   pOutBuf:DWORD
    LOCAL   cbOutBuf:DWORD
    LOCAL   cbTotal:DWORD
    LOCAL   dwRead:DWORD
    LOCAL   dwExit:DWORD
    LOCAL   readBuf[4096]:BYTE

    ;; Create pipe
    mov     sa.nLength, SIZEOF SECURITY_ATTRIBUTES
    mov     sa.lpSecurityDescriptor, 0
    mov     sa.bInheritHandle, TRUE
    invoke  CreatePipe, ADDR hReadPipe, ADDR hWritePipe, ADDR sa, 0
    test    eax, eax
    jz      @ec_fail
    invoke  SetHandleInformation, hReadPipe, HANDLE_FLAG_INHERIT, 0

    ;; Build: "powershell.exe -NoProfile -Command <cmd>"
    invoke  lstrlenA, lpCommand
    add     eax, 64
    invoke  GlobalAlloc, 0, eax
    test    eax, eax
    jz      @ec_pipes
    mov     pCmdLine, eax
    invoke  wsprintfA, pCmdLine, ADDR szPSCmd
    invoke  lstrlenA, pCmdLine
    mov     edx, pCmdLine
    add     edx, eax
    invoke  lstrcpyA, edx, lpCommand

    ;; Setup STARTUPINFO
    invoke  RtlZeroMemory, ADDR sui, SIZEOF STARTUPINFOA
    mov     sui.cb, SIZEOF STARTUPINFOA
    mov     sui.dwFlags, STARTF_USESTDHANDLES or STARTF_USESHOWWINDOW
    mov     sui.wShowWindow, SW_HIDE
    mov     eax, hWritePipe
    mov     sui._hStdOut, eax
    mov     sui._hStdErr, eax
    mov     sui._hStdIn, 0

    ;; CreateProcess
    invoke  CreateProcessA, \
            0, pCmdLine, 0, 0, TRUE, \
            CREATE_NO_WINDOW, 0, 0, ADDR sui, ADDR pi
    test    eax, eax
    jz      @ec_cmd

    invoke  CloseHandle, hWritePipe
    mov     hWritePipe, 0

    ;; Read output into growing buffer
    mov     cbOutBuf, 16384
    invoke  GlobalAlloc, 0, cbOutBuf
    test    eax, eax
    jz      @ec_kill
    mov     pOutBuf, eax
    mov     cbTotal, 0

@ec_read:
    invoke  ReadFile, hReadPipe, ADDR readBuf, 4096, ADDR dwRead, 0
    test    eax, eax
    jz      @ec_done
    cmp     dwRead, 0
    je      @ec_done

    mov     eax, cbTotal
    add     eax, dwRead
    cmp     eax, cbOutBuf
    jle     @ec_copy
    mov     eax, cbOutBuf
    shl     eax, 1
    mov     cbOutBuf, eax
    invoke  GlobalReAlloc, pOutBuf, eax, GMEM_MOVEABLE
    test    eax, eax
    jz      @ec_done
    mov     pOutBuf, eax

@ec_copy:
    mov     edi, pOutBuf
    add     edi, cbTotal
    lea     esi, readBuf
    invoke  RtlMoveMemory, edi, esi, dwRead
    mov     eax, dwRead
    add     cbTotal, eax
    jmp     @ec_read

@ec_done:
    invoke  WaitForSingleObject, pi.hProcess, EXEC_TIMEOUT
    cmp     eax, WAIT_TIMEOUT
    jne     @ec_exited
    invoke  TerminateProcess, pi.hProcess, 1
    invoke  WaitForSingleObject, pi.hProcess, 5000
@ec_exited:
    invoke  GetExitCodeProcess, pi.hProcess, ADDR dwExit
    invoke  CloseHandle, pi.hProcess
    invoke  CloseHandle, pi.hThread
    invoke  CloseHandle, hReadPipe

    ;; Null-terminate + return
    mov     edi, pOutBuf
    add     edi, cbTotal
    mov     byte ptr [edi], 0
    mov     edx, ppOutput
    mov     eax, pOutBuf
    mov     [edx], eax
    mov     edx, pOutputLen
    mov     eax, cbTotal
    mov     [edx], eax
    mov     edx, pExitCode
    mov     eax, dwExit
    mov     [edx], eax

    invoke  GlobalFree, pCmdLine
    xor     eax, eax
    ret

@ec_kill:
    invoke  CloseHandle, pi.hProcess
    invoke  CloseHandle, pi.hThread
@ec_cmd:
    invoke  GlobalFree, pCmdLine
@ec_pipes:
    cmp     hReadPipe, 0
    je      @ec_pw
    invoke  CloseHandle, hReadPipe
@ec_pw:
    cmp     hWritePipe, 0
    je      @ec_fail
    invoke  CloseHandle, hWritePipe
@ec_fail:
    mov     eax, -1
    ret
ExecCommand ENDP
