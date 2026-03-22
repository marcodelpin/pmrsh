;; b64test.asm — Unit tests for base64.inc (RFC 4648)
.686
.model flat, stdcall
option casemap:none

include base64.inc

ExitProcess     PROTO :DWORD
GetStdHandle    PROTO :DWORD
WriteFile       PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
lstrlenA        PROTO :DWORD
lstrcmpA        PROTO :DWORD, :DWORD

STD_OUTPUT_HANDLE equ -11

.data
    szPass      db "  PASS", 13, 10, 0
    szFail      db "  FAIL", 13, 10, 0
    szT1        db "[b64] encode empty", 0
    szT2        db "[b64] encode 'f' → 'Zg=='", 0
    szT3        db "[b64] encode 'fo' → 'Zm8='", 0
    szT4        db "[b64] encode 'foo' → 'Zm9v'", 0
    szT5        db "[b64] encode 'foobar' → 'Zm9vYmFy'", 0
    szT6        db "[b64] decode round-trip 'Hello World'", 0
    ;; RFC 4648 test vectors
    szF         db "f", 0
    szFo        db "fo", 0
    szFoo       db "foo", 0
    szFoobar    db "foobar", 0
    szHello     db "Hello World", 0
    ;; Expected base64
    szB64F      db "Zg==", 0
    szB64Fo     db "Zm8=", 0
    szB64Foo    db "Zm9v", 0
    szB64Foobar db "Zm9vYmFy", 0

.data?
    hStdOut     DWORD ?
    dwWritten   DWORD ?
    outBuf      BYTE 256 dup(?)
    decBuf      BYTE 256 dup(?)

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

    ;; T1: encode empty → 0 length
    invoke  _Print, ADDR szT1
    invoke  Base64Encode, 0, 0, ADDR outBuf
    cmp     eax, 0
    jne     @t1f
    invoke  _PrintResult, 1
    jmp     @t2
@t1f:
    invoke  _PrintResult, 0

@t2:
    ;; T2: encode "f" → "Zg=="
    invoke  _Print, ADDR szT2
    invoke  Base64Encode, ADDR szF, 1, ADDR outBuf
    mov     byte ptr [outBuf + eax], 0
    invoke  lstrcmpA, ADDR outBuf, ADDR szB64F
    test    eax, eax
    jnz     @t2f
    invoke  _PrintResult, 1
    jmp     @t3
@t2f:
    invoke  _PrintResult, 0

@t3:
    ;; T3: encode "fo" → "Zm8="
    invoke  _Print, ADDR szT3
    invoke  Base64Encode, ADDR szFo, 2, ADDR outBuf
    mov     byte ptr [outBuf + eax], 0
    invoke  lstrcmpA, ADDR outBuf, ADDR szB64Fo
    test    eax, eax
    jnz     @t3f
    invoke  _PrintResult, 1
    jmp     @t4
@t3f:
    invoke  _PrintResult, 0

@t4:
    ;; T4: encode "foo" → "Zm9v"
    invoke  _Print, ADDR szT4
    invoke  Base64Encode, ADDR szFoo, 3, ADDR outBuf
    mov     byte ptr [outBuf + eax], 0
    invoke  lstrcmpA, ADDR outBuf, ADDR szB64Foo
    test    eax, eax
    jnz     @t4f
    invoke  _PrintResult, 1
    jmp     @t5
@t4f:
    invoke  _PrintResult, 0

@t5:
    ;; T5: encode "foobar" → "Zm9vYmFy"
    invoke  _Print, ADDR szT5
    invoke  Base64Encode, ADDR szFoobar, 6, ADDR outBuf
    mov     byte ptr [outBuf + eax], 0
    invoke  lstrcmpA, ADDR outBuf, ADDR szB64Foobar
    test    eax, eax
    jnz     @t5f
    invoke  _PrintResult, 1
    jmp     @t6
@t5f:
    invoke  _PrintResult, 0

@t6:
    ;; T6: encode "Hello World" → decode → verify match
    invoke  _Print, ADDR szT6
    invoke  Base64Encode, ADDR szHello, 11, ADDR outBuf
    mov     byte ptr [outBuf + eax], 0
    invoke  Base64Decode, ADDR outBuf, ADDR decBuf, 256
    mov     byte ptr [decBuf + eax], 0
    invoke  lstrcmpA, ADDR decBuf, ADDR szHello
    test    eax, eax
    jnz     @t6f
    invoke  _PrintResult, 1
    jmp     @done
@t6f:
    invoke  _PrintResult, 0

@done:
    invoke  ExitProcess, 0

end start
