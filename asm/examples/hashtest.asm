;; hashtest.asm — Unit tests for hash.inc (Adler32 + MD5)
.686
.model flat, stdcall
option casemap:none

IFNDEF NULL
NULL equ 0
ENDIF
include crypto.inc
include hash.inc

ExitProcess     PROTO :DWORD
GetStdHandle    PROTO :DWORD
WriteFile       PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
wsprintfA       PROTO C :DWORD, :DWORD, :VARARG
lstrlenA        PROTO :DWORD
RtlZeroMemory   PROTO :DWORD, :DWORD

STD_OUTPUT_HANDLE equ -11

.data
    szPass      db "  PASS", 13, 10, 0
    szFail      db "  FAIL", 13, 10, 0
    szT1        db "[hash] Adler32 empty", 0
    szT2        db "[hash] Adler32 'abc'", 0
    szT3        db "[hash] Adler32 known vector", 0
    szT4        db "[hash] MD5 empty", 0
    szT5        db "[hash] MD5 'abc'", 0
    szFmt       db " got=0x%08X", 0
    ;; Test vectors
    szAbc       db "abc", 0
    szWiki      db "Wikipedia", 0
    ;; Adler32("abc") = 0x024D0127
    ;; Adler32("Wikipedia") = 0x11E60398
    ;; MD5("") = d41d8cd98f00b204e9800998ecf8427e
    ;; MD5("abc") = 900150983cd24fb0d6963f7d28e17f72
    md5Empty    db 0D4h, 01Dh, 08Ch, 0D9h, 08Fh, 000h, 0B2h, 004h
                db 0E9h, 080h, 009h, 098h, 0ECh, 0F8h, 042h, 07Eh
    md5Abc      db 090h, 001h, 050h, 098h, 03Ch, 0D2h, 04Fh, 0B0h
                db 0D6h, 096h, 03Fh, 07Dh, 028h, 0E1h, 07Fh, 072h

.data?
    hStdOut     DWORD ?
    dwWritten   DWORD ?
    md5Out      BYTE 16 dup(?)
    szBuf       BYTE 128 dup(?)

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

    ;; Test 1: Adler32 empty → should be 1
    invoke  _Print, ADDR szT1
    invoke  Adler32, 0, 0
    cmp     eax, 1
    je      @t1_pass
    invoke  _PrintResult, 0
    jmp     @t2
@t1_pass:
    invoke  _PrintResult, 1

@t2:
    ;; Test 2: Adler32 "abc" → 0x024D0127
    invoke  _Print, ADDR szT2
    invoke  Adler32, ADDR szAbc, 3
    cmp     eax, 024D0127h
    je      @t2_pass
    push    eax
    invoke  wsprintfA, ADDR szBuf, ADDR szFmt, eax
    invoke  _Print, ADDR szBuf
    pop     eax
    invoke  _PrintResult, 0
    jmp     @t3
@t2_pass:
    invoke  _PrintResult, 1

@t3:
    ;; Test 3: Adler32 "Wikipedia" → 0x11E60398
    invoke  _Print, ADDR szT3
    invoke  Adler32, ADDR szWiki, 9
    cmp     eax, 11E60398h
    je      @t3_pass
    invoke  _PrintResult, 0
    jmp     @t4
@t3_pass:
    invoke  _PrintResult, 1

@t4:
    ;; Test 4: MD5 empty → known hash
    invoke  _Print, ADDR szT4
    invoke  MD5Hash, 0, 0, ADDR md5Out
    ;; Compare 16 bytes
    xor     ecx, ecx
    mov     esi, OFFSET md5Empty
    lea     edi, md5Out
@t4_cmp:
    cmp     ecx, 16
    jge     @t4_pass
    mov     al, [esi + ecx]
    cmp     al, [edi + ecx]
    jne     @t4_fail
    inc     ecx
    jmp     @t4_cmp
@t4_fail:
    invoke  _PrintResult, 0
    jmp     @t5
@t4_pass:
    invoke  _PrintResult, 1

@t5:
    ;; Test 5: MD5 "abc" → known hash
    invoke  _Print, ADDR szT5
    invoke  MD5Hash, ADDR szAbc, 3, ADDR md5Out
    xor     ecx, ecx
    mov     esi, OFFSET md5Abc
    lea     edi, md5Out
@t5_cmp:
    cmp     ecx, 16
    jge     @t5_pass
    mov     al, [esi + ecx]
    cmp     al, [edi + ecx]
    jne     @t5_fail
    inc     ecx
    jmp     @t5_cmp
@t5_fail:
    invoke  _PrintResult, 0
    jmp     @done
@t5_pass:
    invoke  _PrintResult, 1

@done:
    invoke  ExitProcess, 0

end start
