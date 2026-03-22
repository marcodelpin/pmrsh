;; =============================================================================
;; crypto.inc — Cryptographic operations for pmash
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; Provides: CryptoGenKey, CryptoSign, CryptoVerify, CryptoLoadKey,
;;           CryptoSaveKey, CryptoHashSHA256, CryptoRandom
;; Uses BCrypt API (Windows CNG) for:
;;   - Ed25519 key generation/sign/verify (Win10 1903+)
;;   - SHA-256 hashing
;;   - Cryptographic random bytes
;; Requires: bcrypt.lib, kernel32.lib
;; =============================================================================

;; ---- BCrypt constants ----
BCRYPT_SUCCESS              equ 00000000h
STATUS_NOT_SUPPORTED        equ 0C00000BBh

;; ---- BCrypt API Prototypes ----
BCryptOpenAlgorithmProvider PROTO :DWORD, :DWORD, :DWORD, :DWORD
BCryptCloseAlgorithmProvider PROTO :DWORD, :DWORD
BCryptGenerateKeyPair       PROTO :DWORD, :DWORD, :DWORD, :DWORD
BCryptFinalizeKeyPair       PROTO :DWORD, :DWORD
BCryptSignHash              PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
BCryptVerifySignature       PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
BCryptExportKey             PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
BCryptImportKeyPair         PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
BCryptDestroyKey            PROTO :DWORD
BCryptCreateHash            PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
BCryptHashData              PROTO :DWORD, :DWORD, :DWORD, :DWORD
BCryptFinishHash            PROTO :DWORD, :DWORD, :DWORD, :DWORD
BCryptDestroyHash           PROTO :DWORD
BCryptGenRandom             PROTO :DWORD, :DWORD, :DWORD, :DWORD

;; BCryptGenRandom flags
BCRYPT_USE_SYSTEM_PREFERRED_RNG equ 00000002h

;; ---- Kernel32 (if not already defined) ----
IFNDEF _GLOBALALLOC_DEFINED
_GLOBALALLOC_DEFINED equ 1
GlobalAlloc     PROTO :DWORD, :DWORD
GlobalFree      PROTO :DWORD
ENDIF

;; For file I/O (key save/load)
CreateFileA     PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
WriteFile       PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
ReadFile        PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
CloseHandle     PROTO :DWORD
GetFileSize     PROTO :DWORD, :DWORD

GENERIC_READ    equ 80000000h
GENERIC_WRITE   equ 40000000h
CREATE_ALWAYS   equ 2
OPEN_EXISTING   equ 3
INVALID_HANDLE_VALUE equ 0FFFFFFFFh
FILE_ATTRIBUTE_NORMAL equ 80h

;; ---- Wide string constants for BCrypt algorithm names ----
.data
    ;; L"ECDSA_P256" — Ed25519 not in older BCrypt, use ECDSA-P256 as fallback
    ;; L"SHA256"
    szAlgEd25519    dw 'E','C','D','S','A','_','P','2','5','6',0
    szAlgSHA256     dw 'S','H','A','2','5','6',0
    szBlobPriv      dw 'E','C','C','P','R','I','V','A','T','E','B','L','O','B',0
    szBlobPub       dw 'E','C','C','P','U','B','L','I','C','B','L','O','B',0

.data?
    _hAlgSign       DWORD ?     ; algorithm handle for signing
    _hAlgHash       DWORD ?     ; algorithm handle for SHA-256
    _cryptoInited   DWORD ?

.code

;; =============================================================================
;; CryptoInit — Open BCrypt algorithm providers
;; Returns: 0 = success, -1 = error
;; =============================================================================
CryptoInit PROC
    cmp     _cryptoInited, 1
    je      @ci_ok

    ;; Open signing algorithm (ECDSA P-256)
    invoke  BCryptOpenAlgorithmProvider, \
            ADDR _hAlgSign, ADDR szAlgEd25519, NULL, 0
    test    eax, eax
    jnz     @ci_fail

    ;; Open hash algorithm (SHA-256)
    invoke  BCryptOpenAlgorithmProvider, \
            ADDR _hAlgHash, ADDR szAlgSHA256, NULL, 0
    test    eax, eax
    jnz     @ci_fail

    mov     _cryptoInited, 1
@ci_ok:
    xor     eax, eax
    ret
@ci_fail:
    mov     eax, -1
    ret
CryptoInit ENDP

;; =============================================================================
;; CryptoCleanup — Close algorithm providers
;; =============================================================================
CryptoCleanup PROC
    cmp     _cryptoInited, 1
    jne     @cc_done
    cmp     _hAlgSign, 0
    je      @cc_hash
    invoke  BCryptCloseAlgorithmProvider, _hAlgSign, 0
    mov     _hAlgSign, 0
@cc_hash:
    cmp     _hAlgHash, 0
    je      @cc_done
    invoke  BCryptCloseAlgorithmProvider, _hAlgHash, 0
    mov     _hAlgHash, 0
@cc_done:
    mov     _cryptoInited, 0
    ret
CryptoCleanup ENDP

;; =============================================================================
;; CryptoGenKey — Generate ECDSA-P256 key pair
;; Args: phKey (ptr to DWORD, receives key handle)
;; Returns: 0 = success, -1 = error
;; =============================================================================
CryptoGenKey PROC phKey:DWORD
    invoke  BCryptGenerateKeyPair, _hAlgSign, phKey, 256, 0
    test    eax, eax
    jnz     @gk_fail

    ;; Finalize key pair
    mov     edx, phKey
    mov     eax, [edx]
    invoke  BCryptFinalizeKeyPair, eax, 0
    test    eax, eax
    jnz     @gk_fail

    xor     eax, eax
    ret
@gk_fail:
    mov     eax, -1
    ret
CryptoGenKey ENDP

;; =============================================================================
;; CryptoSign — Sign a hash with private key
;; Args: hKey, lpHash (32 bytes), lpSigOut (output buffer), pSigLen (ptr to DWORD)
;; Returns: 0 = success, -1 = error
;; =============================================================================
CryptoSign PROC hKey:DWORD, lpHash:DWORD, lpSigOut:DWORD, pSigLen:DWORD
    invoke  BCryptSignHash, hKey, NULL, \
            lpHash, 32, \
            lpSigOut, 128, pSigLen, 0
    test    eax, eax
    jnz     @cs_fail
    xor     eax, eax
    ret
@cs_fail:
    mov     eax, -1
    ret
CryptoSign ENDP

;; =============================================================================
;; CryptoVerify — Verify signature with public key
;; Args: hKey, lpHash (32 bytes), lpSig, nSigLen
;; Returns: 0 = valid, -1 = invalid/error
;; =============================================================================
CryptoVerify PROC hKey:DWORD, lpHash:DWORD, lpSig:DWORD, nSigLen:DWORD
    invoke  BCryptVerifySignature, hKey, NULL, \
            lpHash, 32, lpSig, nSigLen, 0
    test    eax, eax
    jnz     @cv_fail
    xor     eax, eax
    ret
@cv_fail:
    mov     eax, -1
    ret
CryptoVerify ENDP

;; =============================================================================
;; CryptoHashSHA256 — Hash data with SHA-256
;; Args: lpData, nLen, lpHashOut (32-byte output buffer)
;; Returns: 0 = success, -1 = error
;; =============================================================================
CryptoHashSHA256 PROC lpData:DWORD, nLen:DWORD, lpHashOut:DWORD
    LOCAL   hHash:DWORD

    invoke  BCryptCreateHash, _hAlgHash, ADDR hHash, \
            NULL, 0, NULL, 0, 0
    test    eax, eax
    jnz     @ch_fail

    invoke  BCryptHashData, hHash, lpData, nLen, 0
    test    eax, eax
    jnz     @ch_destroy

    invoke  BCryptFinishHash, hHash, lpHashOut, 32, 0
    push    eax
    invoke  BCryptDestroyHash, hHash
    pop     eax
    test    eax, eax
    jnz     @ch_fail

    xor     eax, eax
    ret

@ch_destroy:
    invoke  BCryptDestroyHash, hHash
@ch_fail:
    mov     eax, -1
    ret
CryptoHashSHA256 ENDP

;; =============================================================================
;; CryptoRandom — Generate cryptographic random bytes
;; Args: lpBuf, nLen
;; Returns: 0 = success, -1 = error
;; =============================================================================
CryptoRandom PROC lpBuf:DWORD, nLen:DWORD
    invoke  BCryptGenRandom, NULL, lpBuf, nLen, \
            BCRYPT_USE_SYSTEM_PREFERRED_RNG
    test    eax, eax
    jnz     @cr_fail
    xor     eax, eax
    ret
@cr_fail:
    mov     eax, -1
    ret
CryptoRandom ENDP

;; =============================================================================
;; CryptoExportKey — Export key to blob (for saving)
;; Args: hKey, bPrivate (1=private, 0=public), ppBlob (ptr to buf ptr), pBlobLen
;; Returns: 0 = success, -1 = error. Caller GlobalFree's the blob.
;; =============================================================================
CryptoExportKey PROC hKey:DWORD, bPrivate:DWORD, ppBlob:DWORD, pBlobLen:DWORD
    LOCAL   pBlobType:DWORD
    LOCAL   cbBlob:DWORD
    LOCAL   pBuf:DWORD

    ;; Select blob type
    cmp     bPrivate, 0
    je      @ek_pub
    lea     eax, szBlobPriv
    jmp     @ek_export
@ek_pub:
    lea     eax, szBlobPub
@ek_export:
    mov     pBlobType, eax

    ;; Query size
    invoke  BCryptExportKey, hKey, NULL, pBlobType, \
            NULL, 0, ADDR cbBlob, 0
    test    eax, eax
    jnz     @ek_fail

    ;; Allocate
    invoke  GlobalAlloc, 0, cbBlob
    test    eax, eax
    jz      @ek_fail
    mov     pBuf, eax

    ;; Export
    invoke  BCryptExportKey, hKey, NULL, pBlobType, \
            pBuf, cbBlob, ADDR cbBlob, 0
    test    eax, eax
    jnz     @ek_free

    ;; Return blob + length
    mov     edx, ppBlob
    mov     eax, pBuf
    mov     [edx], eax
    mov     edx, pBlobLen
    mov     eax, cbBlob
    mov     [edx], eax
    xor     eax, eax
    ret

@ek_free:
    invoke  GlobalFree, pBuf
@ek_fail:
    mov     eax, -1
    ret
CryptoExportKey ENDP

;; =============================================================================
;; CryptoImportKey — Import key from blob
;; Args: lpBlob, nBlobLen, bPrivate, phKey (ptr to key handle)
;; Returns: 0 = success, -1 = error
;; =============================================================================
CryptoImportKey PROC lpBlob:DWORD, nBlobLen:DWORD, bPrivate:DWORD, phKey:DWORD
    LOCAL   pBlobType:DWORD

    cmp     bPrivate, 0
    je      @ik_pub
    lea     eax, szBlobPriv
    jmp     @ik_import
@ik_pub:
    lea     eax, szBlobPub
@ik_import:
    mov     pBlobType, eax

    invoke  BCryptImportKeyPair, _hAlgSign, NULL, pBlobType, \
            phKey, lpBlob, nBlobLen, 0
    test    eax, eax
    jnz     @ik_fail
    xor     eax, eax
    ret
@ik_fail:
    mov     eax, -1
    ret
CryptoImportKey ENDP

;; =============================================================================
;; CryptoSaveKey — Export key and save to file
;; Args: hKey, lpFilePath (ASCIIZ), bPrivate
;; Returns: 0 = success, -1 = error
;; =============================================================================
CryptoSaveKey PROC hKey:DWORD, lpFilePath:DWORD, bPrivate:DWORD
    LOCAL   pBlob:DWORD
    LOCAL   cbBlob:DWORD
    LOCAL   hFile:DWORD
    LOCAL   dwWritten:DWORD

    invoke  CryptoExportKey, hKey, bPrivate, ADDR pBlob, ADDR cbBlob
    test    eax, eax
    jnz     @sk_fail

    invoke  CreateFileA, lpFilePath, GENERIC_WRITE, 0, \
            NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL
    cmp     eax, INVALID_HANDLE_VALUE
    je      @sk_free
    mov     hFile, eax

    invoke  WriteFile, hFile, pBlob, cbBlob, ADDR dwWritten, NULL
    invoke  CloseHandle, hFile
    invoke  GlobalFree, pBlob
    xor     eax, eax
    ret

@sk_free:
    invoke  GlobalFree, pBlob
@sk_fail:
    mov     eax, -1
    ret
CryptoSaveKey ENDP

;; =============================================================================
;; CryptoLoadKey — Load key from file
;; Args: lpFilePath, bPrivate, phKey (ptr to key handle)
;; Returns: 0 = success, -1 = error
;; =============================================================================
CryptoLoadKey PROC lpFilePath:DWORD, bPrivate:DWORD, phKey:DWORD
    LOCAL   hFile:DWORD
    LOCAL   cbFile:DWORD
    LOCAL   pBuf:DWORD
    LOCAL   dwRead:DWORD

    invoke  CreateFileA, lpFilePath, GENERIC_READ, 0, \
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    cmp     eax, INVALID_HANDLE_VALUE
    je      @lk_fail
    mov     hFile, eax

    invoke  GetFileSize, hFile, NULL
    mov     cbFile, eax

    invoke  GlobalAlloc, 0, cbFile
    test    eax, eax
    jz      @lk_close
    mov     pBuf, eax

    invoke  ReadFile, hFile, pBuf, cbFile, ADDR dwRead, NULL
    invoke  CloseHandle, hFile

    invoke  CryptoImportKey, pBuf, cbFile, bPrivate, phKey
    push    eax
    invoke  GlobalFree, pBuf
    pop     eax
    ret

@lk_close:
    invoke  CloseHandle, hFile
@lk_fail:
    mov     eax, -1
    ret
CryptoLoadKey ENDP

;; =============================================================================
;; BytesToHex — Convert binary to hex string
;; Args: lpBytes, nLen, lpHexOut (must be 2*nLen+1 bytes)
;; =============================================================================
BytesToHex PROC uses esi edi lpBytes:DWORD, nLen:DWORD, lpHexOut:DWORD
    LOCAL   hexChars[17]:BYTE

    ;; "0123456789abcdef"
    mov     dword ptr [hexChars], 30313233h
    mov     dword ptr [hexChars+4], 34353637h
    mov     dword ptr [hexChars+8], 38396162h
    mov     dword ptr [hexChars+12], 63646566h
    mov     byte ptr [hexChars+16], 0

    mov     esi, lpBytes
    mov     edi, lpHexOut
    mov     ecx, nLen

@bth_loop:
    test    ecx, ecx
    jz      @bth_done

    movzx   eax, byte ptr [esi]
    mov     edx, eax
    shr     eax, 4
    and     edx, 0Fh
    mov     al, byte ptr [hexChars + eax]
    mov     byte ptr [edi], al
    mov     al, byte ptr [hexChars + edx]
    mov     byte ptr [edi + 1], al

    inc     esi
    add     edi, 2
    dec     ecx
    jmp     @bth_loop

@bth_done:
    mov     byte ptr [edi], 0   ; null terminate
    ret
BytesToHex ENDP
