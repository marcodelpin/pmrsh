;; exectest.asm — ExecCommand test with output + exit code verification
.686
.model flat, stdcall
option casemap:none

NULL equ 0
include exec.inc

IFNDEF _GLOBALALLOC_DEFINED
_GLOBALALLOC_DEFINED equ 1
GlobalAlloc     PROTO :DWORD, :DWORD
GlobalFree      PROTO :DWORD
ENDIF

ExitProcess     PROTO :DWORD
GetStdHandle    PROTO :DWORD
WriteFile       PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
lstrlenA        PROTO :DWORD
wsprintfA       PROTO C :DWORD, :DWORD, :VARARG
lstrcmpA        PROTO :DWORD, :DWORD

STD_OUTPUT_HANDLE equ -11

.data
    szT1    db "[1] exec echo:     ", 0
    szT2    db "[2] exit code 0:   ", 0
    szT3    db "[3] exit code 1:   ", 0
    szT4    db "[4] output match:  ", 0
    szOk    db "OK", 13, 10, 0
    szFail  db "FAIL", 13, 10, 0
    szInfo  db "  output=%d bytes, exit=%d", 13, 10, 0
    szCmd1  db "echo test-output-123", 0
    szCmd3  db "exit 1", 0
    szExpect db "test-output-123", 0

.data?
    hOut    DWORD ?
    nWr     DWORD ?
    pOut    DWORD ?
    nOut    DWORD ?
    nExit   DWORD ?
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

    ;; T1: echo command succeeds
    invoke Print, ADDR szT1
    invoke ExecCommand, ADDR szCmd1, ADDR pOut, ADDR nOut, ADDR nExit
    mov    ebx, eax
    push   ebx
    invoke wsprintfA, ADDR msgBuf, ADDR szInfo, nOut, nExit
    invoke Print, ADDR msgBuf
    pop    ebx
    test   ebx, ebx
    jnz    @t1f
    invoke Print, ADDR szOk
    jmp    @t2
@t1f:
    invoke Print, ADDR szFail

@t2:
    ;; T2: exit code 0
    invoke Print, ADDR szT2
    cmp    nExit, 0
    jne    @t2f
    invoke Print, ADDR szOk
    jmp    @t3
@t2f:
    invoke Print, ADDR szFail

@t3:
    ;; T3: "exit 1" returns code 1
    invoke Print, ADDR szT3
    cmp    pOut, 0
    je     @t3run
    invoke GlobalFree, pOut
@t3run:
    invoke ExecCommand, ADDR szCmd3, ADDR pOut, ADDR nOut, ADDR nExit
    test   eax, eax
    jnz    @t3f
    cmp    nExit, 1
    jne    @t3f
    invoke Print, ADDR szOk
    jmp    @t4
@t3f:
    invoke Print, ADDR szFail

@t4:
    ;; T4: Output contains "test-output-123"
    invoke Print, ADDR szT4
    cmp    pOut, 0
    je     @t4run
    invoke GlobalFree, pOut
@t4run:
    invoke ExecCommand, ADDR szCmd1, ADDR pOut, ADDR nOut, ADDR nExit
    test   eax, eax
    jnz    @t4f
    cmp    nOut, 15
    jb     @t4f
    mov    edx, pOut
    mov    byte ptr [edx + 15], 0
    invoke lstrcmpA, pOut, ADDR szExpect
    test   eax, eax
    jnz    @t4f
    invoke Print, ADDR szOk
    jmp    @done
@t4f:
    invoke Print, ADDR szFail

@done:
    cmp    pOut, 0
    je     @exit
    invoke GlobalFree, pOut
@exit:
    invoke ExitProcess, 0
end start
