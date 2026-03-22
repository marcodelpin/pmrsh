;; cryptotest.asm — Full ECDSA sign/verify round-trip test
.686
.model flat, stdcall
option casemap:none

NULL equ 0
include crypto.inc

ExitProcess      PROTO :DWORD
GetStdHandle     PROTO :DWORD
WriteFile        PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
lstrlenA         PROTO :DWORD
wsprintfA        PROTO C :DWORD, :DWORD, :VARARG
RtlZeroMemory    PROTO :DWORD, :DWORD

IFNDEF _GLOBALALLOC_DEFINED
_GLOBALALLOC_DEFINED equ 1
GlobalAlloc     PROTO :DWORD, :DWORD
GlobalFree      PROTO :DWORD
ENDIF

STD_OUTPUT_HANDLE equ -11

.data
    szInit      db "[1] CryptoInit:    ", 0
    szGenKey    db "[2] CryptoGenKey:  ", 0
    szHash      db "[3] SHA256 hash:   ", 0
    szSign      db "[4] CryptoSign:    ", 0
    szExport    db "[5] ExportPubKey:  ", 0
    szImport    db "[6] ImportPubKey:  ", 0
    szVerify    db "[7] CryptoVerify:  ", 0
    szOk        db "OK", 13, 10, 0
    szFail      db "FAIL", 13, 10, 0
    szSigLen    db "    sig length: %d bytes", 13, 10, 0
    szPubLen    db "    pub length: %d bytes", 13, 10, 0
    szCRLF      db 13, 10, 0
    szNonce     db "this is a 32-byte test nonce!!!!",0  ; exactly 32 bytes incl NUL

.data?
    hStdOut     DWORD ?
    dwWr        DWORD ?
    hKey        DWORD ?
    hKey2       DWORD ?
    hashBuf     BYTE 32 dup(?)
    sigBuf      BYTE 128 dup(?)
    sigLen      DWORD ?
    pPubBlob    DWORD ?
    cbPubBlob   DWORD ?
    msgBuf      BYTE 256 dup(?)

.code

Print PROC lpStr:DWORD
    invoke lstrlenA, lpStr
    invoke WriteFile, hStdOut, lpStr, eax, ADDR dwWr, 0
    ret
Print ENDP

PrintResult PROC bSuccess:DWORD
    cmp bSuccess, 0
    jne @pr_fail
    invoke Print, ADDR szOk
    ret
@pr_fail:
    invoke Print, ADDR szFail
    ret
PrintResult ENDP

start:
    invoke GetStdHandle, STD_OUTPUT_HANDLE
    mov    hStdOut, eax

    ;; Step 1: Init
    invoke Print, ADDR szInit
    invoke CryptoInit
    mov    ebx, eax
    invoke PrintResult, ebx
    test   ebx, ebx
    jnz    @done

    ;; Step 2: Generate key
    invoke Print, ADDR szGenKey
    invoke CryptoGenKey, ADDR hKey
    mov    ebx, eax
    invoke PrintResult, ebx
    test   ebx, ebx
    jnz    @done

    ;; Step 3: Hash nonce
    invoke Print, ADDR szHash
    invoke CryptoHashSHA256, ADDR szNonce, 32, ADDR hashBuf
    mov    ebx, eax
    invoke PrintResult, ebx
    test   ebx, ebx
    jnz    @done

    ;; Step 4: Sign the hash
    invoke Print, ADDR szSign
    invoke CryptoSign, hKey, ADDR hashBuf, ADDR sigBuf, ADDR sigLen
    mov    ebx, eax
    invoke PrintResult, ebx
    invoke wsprintfA, ADDR msgBuf, ADDR szSigLen, sigLen
    invoke Print, ADDR msgBuf
    test   ebx, ebx
    jnz    @done

    ;; Step 5: Export public key blob
    invoke Print, ADDR szExport
    invoke CryptoExportKey, hKey, 0, ADDR pPubBlob, ADDR cbPubBlob
    mov    ebx, eax
    invoke PrintResult, ebx
    invoke wsprintfA, ADDR msgBuf, ADDR szPubLen, cbPubBlob
    invoke Print, ADDR msgBuf
    test   ebx, ebx
    jnz    @done

    ;; Step 6: Import public key into a NEW key handle
    invoke Print, ADDR szImport
    invoke CryptoImportKey, pPubBlob, cbPubBlob, 0, ADDR hKey2
    mov    ebx, eax
    invoke PrintResult, ebx
    test   ebx, ebx
    jnz    @done

    ;; Step 7: Verify signature with the IMPORTED public key
    invoke Print, ADDR szVerify
    invoke CryptoVerify, hKey2, ADDR hashBuf, ADDR sigBuf, sigLen
    invoke PrintResult, eax

    ;; Cleanup
    invoke GlobalFree, pPubBlob
    invoke BCryptDestroyKey, hKey
    invoke BCryptDestroyKey, hKey2
    invoke CryptoCleanup

@done:
    invoke ExitProcess, 0
end start
