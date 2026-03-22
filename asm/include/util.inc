;; =============================================================================
;; util.inc — Console I/O and logging utilities
;; Part of pmash — lightweight remote agent
;; =============================================================================

WriteFile       PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
CreateFileA     PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
CloseHandle     PROTO :DWORD
SetFilePointer  PROTO :DWORD, :DWORD, :DWORD, :DWORD
lstrlenA        PROTO :DWORD

IFNDEF GENERIC_WRITE
GENERIC_WRITE   equ 40000000h
ENDIF
IFNDEF FILE_ATTRIBUTE_NORMAL
FILE_ATTRIBUTE_NORMAL equ 80h
ENDIF
IFNDEF INVALID_HANDLE_VALUE
INVALID_HANDLE_VALUE equ 0FFFFFFFFh
ENDIF

.data
    _szLogPath  db "C:\ProgramData\mrsh\mrsh.log", 0

.data?
    _hStdOut    DWORD ?
    _hStdErr    DWORD ?
    _dwWritten  DWORD ?

.code

;; Print string to stdout (works with pipes via WriteFile)
StdOut PROC lpStr:DWORD
    LOCAL nLen:DWORD
    invoke lstrlenA, lpStr
    mov    nLen, eax
    invoke WriteFile, _hStdOut, lpStr, nLen, ADDR _dwWritten, 0
    ret
StdOut ENDP

;; Print string to stderr
StdErr PROC lpStr:DWORD
    LOCAL nLen:DWORD
    invoke lstrlenA, lpStr
    mov    nLen, eax
    invoke WriteFile, _hStdErr, lpStr, nLen, ADDR _dwWritten, 0
    ret
StdErr ENDP

;; Append message to log file
LogMsg PROC lpStr:DWORD
    LOCAL   hLog:DWORD
    LOCAL   nLen:DWORD
    LOCAL   nWr:DWORD
    invoke  CreateFileA, ADDR _szLogPath, GENERIC_WRITE, 1, \
            0, 4, FILE_ATTRIBUTE_NORMAL, 0
    cmp     eax, INVALID_HANDLE_VALUE
    je      @log_done
    mov     hLog, eax
    invoke  SetFilePointer, hLog, 0, 0, 2
    invoke  lstrlenA, lpStr
    mov     nLen, eax
    invoke  WriteFile, hLog, lpStr, nLen, ADDR nWr, 0
    invoke  CloseHandle, hLog
@log_done:
    ret
LogMsg ENDP
