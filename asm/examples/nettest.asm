;; =============================================================================
;; nettest.asm — Test program for net.inc module
;; Builds as console app. Tests TCP init/cleanup.
;; =============================================================================

.686
.model flat, stdcall
option casemap:none

include net.inc

;; ---- Kernel32 ----
GetModuleHandleA    PROTO :DWORD
ExitProcess         PROTO :DWORD
lstrlenA            PROTO :DWORD

;; ---- Console output ----
GetStdHandle        PROTO :DWORD
WriteConsoleA       PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
STD_OUTPUT_HANDLE   equ -11

.data
    szInitOk    db "Winsock initialized OK", 13, 10, 0
    szInitFail  db "Winsock init FAILED", 13, 10, 0
    szCleanup   db "Winsock cleaned up", 13, 10, 0
    szDone      db "Test complete.", 13, 10, 0

.data?
    hStdOut     DWORD ?
    dwWritten   DWORD ?

.code

;; ---- Print string to console ----
ConPrint PROC lpStr:DWORD
    LOCAL   nLen:DWORD
    invoke  lstrlenA, lpStr
    mov     nLen, eax
    invoke  WriteConsoleA, hStdOut, lpStr, nLen, ADDR dwWritten, 0
    ret
ConPrint ENDP

;; ---- Entry point ----
start:
    invoke  GetStdHandle, STD_OUTPUT_HANDLE
    mov     hStdOut, eax

    ;; Initialize Winsock
    invoke  NetInit
    test    eax, eax
    jnz     @fail

    invoke  ConPrint, ADDR szInitOk

    ;; Cleanup
    invoke  NetCleanup
    invoke  ConPrint, ADDR szCleanup
    invoke  ConPrint, ADDR szDone

    invoke  ExitProcess, 0

@fail:
    invoke  ConPrint, ADDR szInitFail
    invoke  ExitProcess, 1

end start
