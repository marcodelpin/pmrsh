;; jsontest.asm — Unit tests for json.inc (JsonFind parser)
.686
.model flat, stdcall
option casemap:none

include json.inc

ExitProcess     PROTO :DWORD
GetStdHandle    PROTO :DWORD
WriteFile       PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
lstrcmpA        PROTO :DWORD, :DWORD

STD_OUTPUT_HANDLE equ -11

.data
    szPass      db "  PASS", 13, 10, 0
    szFail      db "  FAIL", 13, 10, 0
    szT1        db "[json] find string value", 0
    szT2        db "[json] find number value", 0
    szT3        db "[json] find bool value", 0
    szT4        db "[json] key not found", 0
    szT5        db "[json] nested key", 0
    ;; Test data
    szJson1     db '{"name":"alice","age":30,"active":true}', 0
    szKeyName   db "name", 0
    szKeyAge    db "age", 0
    szKeyActive db "active", 0
    szKeyMissing db "email", 0
    szExpAlice  db "alice", 0
    szExp30     db "30", 0
    szExpTrue   db "true", 0

.data?
    hStdOut     DWORD ?
    dwWritten   DWORD ?
    outBuf      BYTE 256 dup(?)

.code

_Print PROC lpStr:DWORD
    invoke  lstrlenA, lpStr
    invoke  WriteFile, hStdOut, lpStr, eax, ADDR dwWritten, 0
    ret
_Print ENDP

_PrintResult PROC bPass:DWORD
    cmp     bPass, 1
    je      @pr_pass
    invoke  _Print, ADDR szFail
    ret
@pr_pass:
    invoke  _Print, ADDR szPass
    ret
_PrintResult ENDP

start:
    invoke  GetStdHandle, STD_OUTPUT_HANDLE
    mov     hStdOut, eax

    ;; T1: find "name" → "alice"
    invoke  _Print, ADDR szT1
    invoke  JsonFind, ADDR szJson1, ADDR szKeyName, ADDR outBuf, 255
    test    eax, eax
    jz      @t1f
    invoke  lstrcmpA, ADDR outBuf, ADDR szExpAlice
    test    eax, eax
    jnz     @t1f
    invoke  _PrintResult, 1
    jmp     @t2
@t1f:
    invoke  _PrintResult, 0

@t2:
    ;; T2: find "age" → "30"
    invoke  _Print, ADDR szT2
    invoke  JsonFind, ADDR szJson1, ADDR szKeyAge, ADDR outBuf, 255
    test    eax, eax
    jz      @t2f
    invoke  lstrcmpA, ADDR outBuf, ADDR szExp30
    test    eax, eax
    jnz     @t2f
    invoke  _PrintResult, 1
    jmp     @t3
@t2f:
    invoke  _PrintResult, 0

@t3:
    ;; T3: find "active" → "true"
    invoke  _Print, ADDR szT3
    invoke  JsonFind, ADDR szJson1, ADDR szKeyActive, ADDR outBuf, 255
    test    eax, eax
    jz      @t3f
    invoke  lstrcmpA, ADDR outBuf, ADDR szExpTrue
    test    eax, eax
    jnz     @t3f
    invoke  _PrintResult, 1
    jmp     @t4
@t3f:
    invoke  _PrintResult, 0

@t4:
    ;; T4: key not found → returns 0
    invoke  _Print, ADDR szT4
    invoke  JsonFind, ADDR szJson1, ADDR szKeyMissing, ADDR outBuf, 255
    cmp     eax, 0
    jne     @t4f
    invoke  _PrintResult, 1
    jmp     @done
@t4f:
    invoke  _PrintResult, 0

@done:
    invoke  ExitProcess, 0

end start
