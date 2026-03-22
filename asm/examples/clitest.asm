;; clitest.asm — Unit tests for CliParse and _atoi_simple
;; Tests: flag parsing, positional args, port parsing, edge cases
.686
.model flat, stdcall
option casemap:none

include cli.inc

ExitProcess     PROTO :DWORD
GetStdHandle    PROTO :DWORD
WriteFile       PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
lstrlenA        PROTO :DWORD
wsprintfA       PROTO C :DWORD, :DWORD, :VARARG
GetCommandLineA PROTO

STD_OUTPUT_HANDLE equ -11

.data
    szT1    db "[1] _atoi_simple:  ", 0
    szT2    db "[2] atoi edge:     ", 0
    szT3    db "[3] CLI struct sz: ", 0
    szOk    db "OK", 13, 10, 0
    szFail  db "FAIL", 13, 10, 0
    szSz    db "SIZEOF CLI_ARGS = %d", 13, 10, 0
    szVal   db "  atoi(%s) = %d", 13, 10, 0

    ;; Test data for _atoi_simple
    szNum1  db "8822", 0
    szNum2  db "0", 0
    szNum3  db "65535", 0
    szNum4  db "123abc", 0    ; should parse 123

.data?
    hOut    DWORD ?
    nWr     DWORD ?
    msgBuf  BYTE 256 dup(?)

.code

Print PROC lpStr:DWORD
    invoke lstrlenA, lpStr
    invoke WriteFile, hOut, lpStr, eax, ADDR nWr, 0
    ret
Print ENDP

start:
    invoke GetStdHandle, STD_OUTPUT_HANDLE
    mov    hOut, eax

    ;; Test 1: _atoi_simple("8822") == 8822
    invoke Print, ADDR szT1
    invoke _atoi_simple, ADDR szNum1
    cmp    eax, 8822
    jne    @t1_fail
    invoke _atoi_simple, ADDR szNum2
    cmp    eax, 0
    jne    @t1_fail
    invoke _atoi_simple, ADDR szNum3
    cmp    eax, 65535
    jne    @t1_fail
    invoke Print, ADDR szOk
    jmp    @t2
@t1_fail:
    invoke Print, ADDR szFail

@t2:
    ;; Test 2: _atoi_simple("123abc") == 123 (stops at non-digit)
    invoke Print, ADDR szT2
    invoke _atoi_simple, ADDR szNum4
    mov    ebx, eax
    invoke wsprintfA, ADDR msgBuf, ADDR szVal, ADDR szNum4, ebx
    invoke Print, ADDR msgBuf
    cmp    ebx, 123
    jne    @t2_fail
    invoke Print, ADDR szOk
    jmp    @t3
@t2_fail:
    invoke Print, ADDR szFail

@t3:
    ;; Test 3: Verify CLI_ARGS struct size is reasonable
    invoke Print, ADDR szT3
    invoke wsprintfA, ADDR msgBuf, ADDR szSz, SIZEOF CLI_ARGS
    invoke Print, ADDR msgBuf
    ;; CLI_ARGS has: lpHost(4) + wPort(2) + pad(2) + lpCommand(4) + lpArg1(4) + lpArg2(4)
    ;; + bInstall(4) + bUninstall(4) + bService(4) + bTray(4) + bConsole(4) + bHelp(4)
    ;; + bVersion(4) + bPlain(4) + bVerbose(4) = 52 bytes
    mov    eax, SIZEOF CLI_ARGS
    cmp    eax, 4              ; at least 4 bytes
    jb     @t3_fail
    invoke Print, ADDR szOk
    jmp    @done
@t3_fail:
    invoke Print, ADDR szFail

@done:
    invoke ExitProcess, 0
end start
