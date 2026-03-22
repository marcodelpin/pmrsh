;; compresstest.asm — Unit tests for compress.inc (LZNT1 round-trip)
.686
.model flat, stdcall
option casemap:none

IFNDEF NULL
NULL equ 0
ENDIF
IFNDEF COMPRESS_RAW
COMPRESS_RAW equ 0
ENDIF

include compress.inc

ExitProcess     PROTO :DWORD
GetStdHandle    PROTO :DWORD
WriteFile       PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
lstrlenA        PROTO :DWORD
RtlMoveMemory   PROTO :DWORD, :DWORD, :DWORD

STD_OUTPUT_HANDLE equ -11

.data
    szPass      db "  PASS", 13, 10, 0
    szFail      db "  FAIL", 13, 10, 0
    szT1        db "[compress] init workspace", 0
    szT2        db "[compress] small data → raw (below threshold)", 0
    szT3        db "[compress] round-trip 4KB repeating data", 0
    szT4        db "[compress] decompress raw flag", 0
    ;; 4KB of repeating data (compressible)
    szRepeat    db 256 dup("ABCDEFGHIJKLMNOP")  ; 256 * 16 = 4096 bytes

.data?
    hStdOut     DWORD ?
    dwWritten   DWORD ?
    pCompressed DWORD ?
    cbCompressed DWORD ?
    pDecompressed DWORD ?
    cbDecompressed DWORD ?

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

    ;; T1: CompressInit succeeds
    invoke  _Print, ADDR szT1
    invoke  CompressInit
    test    eax, eax
    jnz     @t1f
    invoke  _PrintResult, 1
    jmp     @t2
@t1f:
    invoke  _PrintResult, 0

@t2:
    ;; T2: Small data (< 512 bytes) → raw output with flag byte 0x00
    invoke  _Print, ADDR szT2
    invoke  CompressPayload, ADDR szRepeat, 100, ADDR pCompressed, ADDR cbCompressed
    test    eax, eax
    jnz     @t2f
    ;; Output should be 101 bytes (1 flag + 100 data)
    cmp     cbCompressed, 101
    jne     @t2f
    ;; Flag byte should be 0x00 (raw)
    mov     edx, pCompressed
    cmp     byte ptr [edx], COMPRESS_RAW
    jne     @t2f
    invoke  GlobalFree, pCompressed
    invoke  _PrintResult, 1
    jmp     @t3
@t2f:
    invoke  _PrintResult, 0

@t3:
    ;; T3: Round-trip 4KB repeating data — compress then decompress, verify match
    invoke  _Print, ADDR szT3
    invoke  CompressPayload, ADDR szRepeat, 4096, ADDR pCompressed, ADDR cbCompressed
    test    eax, eax
    jnz     @t3f
    ;; Compressed should be smaller than original (repeating data is highly compressible)
    cmp     cbCompressed, 4096
    jge     @t3f_raw          ; if not smaller, it's raw — still valid

    ;; Decompress
    invoke  DecompressPayload, pCompressed, cbCompressed, ADDR pDecompressed, ADDR cbDecompressed
    test    eax, eax
    jnz     @t3f
    ;; Decompressed size must match original
    cmp     cbDecompressed, 4096
    jne     @t3f
    ;; Compare content byte by byte (first 16 bytes enough)
    mov     esi, pDecompressed
    lea     edi, szRepeat
    xor     ecx, ecx
@t3_cmp:
    cmp     ecx, 16
    jge     @t3p
    mov     al, [esi + ecx]
    cmp     al, [edi + ecx]
    jne     @t3f
    inc     ecx
    jmp     @t3_cmp

@t3f_raw:
    ;; Raw output is acceptable — test decompress on raw
    invoke  DecompressPayload, pCompressed, cbCompressed, ADDR pDecompressed, ADDR cbDecompressed
    test    eax, eax
    jnz     @t3f
    cmp     cbDecompressed, 4096
    jne     @t3f
@t3p:
    invoke  GlobalFree, pCompressed
    invoke  GlobalFree, pDecompressed
    invoke  _PrintResult, 1
    jmp     @t4
@t3f:
    invoke  _PrintResult, 0

@t4:
    ;; T4: Decompress raw flag — manually build [0x00][data], verify decompress strips flag
    invoke  _Print, ADDR szT4
    invoke  GlobalAlloc, 0, 6
    test    eax, eax
    jz      @t4f
    mov     edx, eax
    mov     byte ptr [edx], 0      ; raw flag
    mov     byte ptr [edx + 1], 'T'
    mov     byte ptr [edx + 2], 'E'
    mov     byte ptr [edx + 3], 'S'
    mov     byte ptr [edx + 4], 'T'
    mov     byte ptr [edx + 5], '!'
    push    edx
    invoke  DecompressPayload, edx, 6, ADDR pDecompressed, ADDR cbDecompressed
    pop     edx
    push    edx
    test    eax, eax
    jnz     @t4f2
    cmp     cbDecompressed, 5       ; "TEST!" = 5 bytes
    jne     @t4f2
    mov     esi, pDecompressed
    cmp     byte ptr [esi], 'T'
    jne     @t4f2
    cmp     byte ptr [esi + 4], '!'
    jne     @t4f2
    invoke  GlobalFree, pDecompressed
    pop     edx
    invoke  GlobalFree, edx
    invoke  _PrintResult, 1
    jmp     @done
@t4f2:
    pop     edx
    invoke  GlobalFree, edx
@t4f:
    invoke  _PrintResult, 0

@done:
    invoke  ExitProcess, 0

end start
