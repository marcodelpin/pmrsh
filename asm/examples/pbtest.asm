;; pbtest.asm — Unit tests for protobuf.inc (varint + field encoding)
.686
.model flat, stdcall
option casemap:none

include protobuf.inc

ExitProcess     PROTO :DWORD
GetStdHandle    PROTO :DWORD
WriteFile       PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
lstrlenA        PROTO :DWORD

STD_OUTPUT_HANDLE equ -11

.data
    szPass      db "  PASS", 13, 10, 0
    szFail      db "  FAIL", 13, 10, 0
    szT1        db "[pb] varint encode 0", 0
    szT2        db "[pb] varint encode 1", 0
    szT3        db "[pb] varint encode 127", 0
    szT4        db "[pb] varint encode 128", 0
    szT5        db "[pb] varint encode 300", 0
    szT6        db "[pb] varint decode round-trip 12345", 0
    szT7        db "[pb] WriteString field", 0
    szT8        db "[pb] WriteInt32 field", 0
    szHello     db "hello", 0

.data?
    hStdOut     DWORD ?
    dwWritten   DWORD ?
    buf         BYTE 256 dup(?)
    pRead       DWORD ?
    decoded     DWORD ?

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

    ;; T1: varint encode 0 → 1 byte (0x00)
    invoke  _Print, ADDR szT1
    invoke  PbEncodeVarint, ADDR buf, 0
    cmp     eax, 1
    jne     @t1f
    cmp     byte ptr [buf], 0
    jne     @t1f
    invoke  _PrintResult, 1
    jmp     @t2
@t1f:
    invoke  _PrintResult, 0

@t2:
    ;; T2: varint encode 1 → 1 byte (0x01)
    invoke  _Print, ADDR szT2
    invoke  PbEncodeVarint, ADDR buf, 1
    cmp     eax, 1
    jne     @t2f
    cmp     byte ptr [buf], 1
    jne     @t2f
    invoke  _PrintResult, 1
    jmp     @t3
@t2f:
    invoke  _PrintResult, 0

@t3:
    ;; T3: varint encode 127 → 1 byte (0x7F)
    invoke  _Print, ADDR szT3
    invoke  PbEncodeVarint, ADDR buf, 127
    cmp     eax, 1
    jne     @t3f
    cmp     byte ptr [buf], 7Fh
    jne     @t3f
    invoke  _PrintResult, 1
    jmp     @t4
@t3f:
    invoke  _PrintResult, 0

@t4:
    ;; T4: varint encode 128 → 2 bytes (0x80 0x01)
    invoke  _Print, ADDR szT4
    invoke  PbEncodeVarint, ADDR buf, 128
    cmp     eax, 2
    jne     @t4f
    cmp     byte ptr [buf], 80h
    jne     @t4f
    cmp     byte ptr [buf + 1], 01h
    jne     @t4f
    invoke  _PrintResult, 1
    jmp     @t5
@t4f:
    invoke  _PrintResult, 0

@t5:
    ;; T5: varint encode 300 → 2 bytes (0xAC 0x02)
    invoke  _Print, ADDR szT5
    invoke  PbEncodeVarint, ADDR buf, 300
    cmp     eax, 2
    jne     @t5f
    cmp     byte ptr [buf], 0ACh
    jne     @t5f
    cmp     byte ptr [buf + 1], 02h
    jne     @t5f
    invoke  _PrintResult, 1
    jmp     @t6
@t5f:
    invoke  _PrintResult, 0

@t6:
    ;; T6: varint encode+decode round-trip 12345
    invoke  _Print, ADDR szT6
    invoke  PbEncodeVarint, ADDR buf, 12345
    lea     eax, buf
    mov     pRead, eax
    invoke  PbDecodeVarint, ADDR pRead, ADDR decoded
    cmp     decoded, 12345
    jne     @t6f
    invoke  _PrintResult, 1
    jmp     @t7
@t6f:
    invoke  _PrintResult, 0

@t7:
    ;; T7: WriteString — field 1, "hello" → tag(0x0A) + len(5) + "hello"
    invoke  _Print, ADDR szT7
    invoke  PbWriteString, ADDR buf, 1, ADDR szHello
    cmp     eax, 7              ; 1(tag) + 1(len) + 5(data) = 7
    jne     @t7f
    cmp     byte ptr [buf], 0Ah ; tag = (1 << 3) | 2 = 0x0A
    jne     @t7f
    cmp     byte ptr [buf + 1], 5 ; length = 5
    jne     @t7f
    cmp     byte ptr [buf + 2], 'h'
    jne     @t7f
    invoke  _PrintResult, 1
    jmp     @t8
@t7f:
    invoke  _PrintResult, 0

@t8:
    ;; T8: WriteInt32 — field 2, value 42 → tag(0x10) + varint(42)
    invoke  _Print, ADDR szT8
    invoke  PbWriteInt32, ADDR buf, 2, 42
    cmp     eax, 2              ; 1(tag) + 1(varint) = 2
    jne     @t8f
    cmp     byte ptr [buf], 10h ; tag = (2 << 3) | 0 = 0x10
    jne     @t8f
    cmp     byte ptr [buf + 1], 42
    jne     @t8f
    invoke  _PrintResult, 1
    jmp     @done
@t8f:
    invoke  _PrintResult, 0

@done:
    invoke  ExitProcess, 0

end start
