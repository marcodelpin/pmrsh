.686
.model flat, stdcall
option casemap:none

include net.inc
include tls.inc

RtlMoveMemory   PROTO :DWORD, :DWORD, :DWORD
GetStdHandle     PROTO :DWORD
WriteConsoleA    PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
ExitProcess      PROTO :DWORD
lstrlenA         PROTO :DWORD

STD_OUTPUT_HANDLE equ -11

.data
    szOk    db "TLS module compiled OK", 13, 10, 0

.data?
    hStdOut DWORD ?
    dwWr    DWORD ?
    tlsCtx  TLS_CTX <>

.code
start:
    invoke GetStdHandle, STD_OUTPUT_HANDLE
    mov    hStdOut, eax

    invoke NetInit
    invoke TlsInit, ADDR tlsCtx, 0
    invoke TlsClose, ADDR tlsCtx
    invoke NetCleanup

    invoke lstrlenA, ADDR szOk
    invoke WriteConsoleA, hStdOut, ADDR szOk, eax, ADDR dwWr, 0
    invoke ExitProcess, 0
end start
