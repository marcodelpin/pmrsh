;; =============================================================================
;; sync.inc — Delta sync: block signatures + delta transfer
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; Block-level delta using Adler32 (weak) + MD5 (strong) signatures.
;; Block size: 4096 bytes. Wire format: M/D/E binary markers.
;; Requires: hash.inc (Adler32, MD5Hash), proto.inc, tls.inc
;; =============================================================================

MoveFileExA     PROTO :DWORD, :DWORD, :DWORD
DeleteFileA     PROTO :DWORD
wsprintfA       PROTO C :DWORD, :DWORD, :VARARG

SYNC_BLOCK_SIZE     equ 4096

;; Delta stream markers (inside CMD_SYNC_RESP payload)
DELTA_MATCH         equ 'M'     ; 1-byte marker + 4-byte BE block index
DELTA_DATA          equ 'D'     ; 1-byte marker + 4-byte BE data length + raw data
DELTA_END           equ 'E'     ; 1-byte marker (end of delta stream)

.data
    _szSyncTmpFmt db "%s.sync.tmp", 0

.code

;; =============================================================================
;; SyncComputeSignatures — Compute block signatures for a file
;; Args: lpFilePath, pSigBuf (output: array of {u32 index, u32 adler32, u8[16] md5})
;;       pSigCount (output: number of blocks)
;; Returns: 0 = success, -1 = error. Caller GlobalFree's pSigBuf.
;; Each signature entry = 24 bytes: [4:index][4:adler32][16:md5]
;; =============================================================================
SyncComputeSignatures PROC uses ebx esi edi \
    lpFilePath:DWORD, pSigBuf:DWORD, pSigCount:DWORD

    LOCAL   hFile:DWORD
    LOCAL   cbFile:DWORD
    LOCAL   nBlocks:DWORD
    LOCAL   pBuf:DWORD
    LOCAL   pSigs:DWORD
    LOCAL   dwRead:DWORD
    LOCAL   blockBuf[SYNC_BLOCK_SIZE]:BYTE
    LOCAL   md5Out[16]:BYTE

    ;; Open file
    invoke  CreateFileA, lpFilePath, GENERIC_READ, 1, \
            0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0
    cmp     eax, INVALID_HANDLE_VALUE
    je      @scs_fail
    mov     hFile, eax

    invoke  GetFileSize, hFile, 0
    mov     cbFile, eax

    ;; Calculate number of blocks
    mov     eax, cbFile
    add     eax, SYNC_BLOCK_SIZE - 1
    xor     edx, edx
    mov     ecx, SYNC_BLOCK_SIZE
    div     ecx
    mov     nBlocks, eax
    cmp     eax, 0
    je      @scs_empty

    ;; Allocate signature array (24 bytes per block)
    mov     eax, nBlocks
    imul    eax, 24
    invoke  GlobalAlloc, 0, eax
    test    eax, eax
    jz      @scs_close
    mov     pSigs, eax

    ;; Read blocks and compute signatures
    xor     ebx, ebx            ; block index
@scs_loop:
    cmp     ebx, nBlocks
    jge     @scs_done
    invoke  ReadFile, hFile, ADDR blockBuf, SYNC_BLOCK_SIZE, ADDR dwRead, 0
    test    eax, eax
    jz      @scs_done
    cmp     dwRead, 0
    je      @scs_done

    ;; Compute signature for this block
    mov     edi, pSigs
    mov     eax, ebx
    imul    eax, 24
    add     edi, eax            ; edi = &sigs[blockIndex]

    ;; Store block index
    mov     [edi], ebx

    ;; Adler32
    invoke  Adler32, ADDR blockBuf, dwRead
    mov     [edi + 4], eax

    ;; MD5
    invoke  MD5Hash, ADDR blockBuf, dwRead, ADDR md5Out
    ;; Copy 16 bytes of MD5 hash
    invoke  RtlMoveMemory, ADDR [edi + 8], ADDR md5Out, 16

    inc     ebx
    jmp     @scs_loop

@scs_done:
    invoke  CloseHandle, hFile
    mov     edx, pSigBuf
    mov     eax, pSigs
    mov     [edx], eax
    mov     edx, pSigCount
    mov     eax, nBlocks
    mov     [edx], eax
    xor     eax, eax
    ret

@scs_empty:
    invoke  CloseHandle, hFile
    mov     edx, pSigBuf
    mov     dword ptr [edx], 0
    mov     edx, pSigCount
    mov     dword ptr [edx], 0
    xor     eax, eax
    ret

@scs_close:
    invoke  CloseHandle, hFile
@scs_fail:
    mov     eax, -1
    ret
SyncComputeSignatures ENDP

;; =============================================================================
;; SyncSendDelta — Send delta stream: compare local file against remote sigs
;; Args: pTlsCtx, lpFilePath, pRemoteSigs (24-byte entries), nRemoteSigCount
;; Sends: CMD_SYNC_RESP messages with M/D/E markers
;; Returns: 0 = success
;; =============================================================================
SyncSendDelta PROC uses ebx esi edi \
    pTlsCtx:DWORD, lpFilePath:DWORD, pRemoteSigs:DWORD, nRemoteSigCount:DWORD

    LOCAL   hFile:DWORD
    LOCAL   blockBuf[SYNC_BLOCK_SIZE]:BYTE
    LOCAL   dwRead:DWORD
    LOCAL   adler:DWORD
    LOCAL   md5Out[16]:BYTE
    LOCAL   marker[9]:BYTE      ; 1-byte marker + 4-byte BE index/length + padding
    LOCAL   blockIdx:DWORD
    LOCAL   pDeltaBuf:DWORD
    LOCAL   cbDelta:DWORD

    invoke  CreateFileA, lpFilePath, GENERIC_READ, 1, \
            0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0
    cmp     eax, INVALID_HANDLE_VALUE
    je      @ssd_fail
    mov     hFile, eax
    mov     blockIdx, 0

@ssd_loop:
    invoke  ReadFile, hFile, ADDR blockBuf, SYNC_BLOCK_SIZE, ADDR dwRead, 0
    test    eax, eax
    jz      @ssd_end
    cmp     dwRead, 0
    je      @ssd_end

    ;; Compute Adler32 for this block
    invoke  Adler32, ADDR blockBuf, dwRead
    mov     adler, eax

    ;; Search remote signatures for a match (weak hash first)
    mov     esi, pRemoteSigs
    xor     ecx, ecx            ; sig index
@ssd_search:
    cmp     ecx, nRemoteSigCount
    jge     @ssd_no_match
    cmp     [esi + 4], eax      ; compare adler32
    jne     @ssd_next_sig
    ;; Weak match — verify strong hash (MD5)
    push    ecx
    invoke  MD5Hash, ADDR blockBuf, dwRead, ADDR md5Out
    pop     ecx
    ;; Compare 16 bytes of MD5
    push    ecx
    lea     edi, [esi + 8]      ; remote MD5
    lea     ebx, md5Out
    mov     ecx, 16
@ssd_md5cmp:
    mov     al, [edi]
    cmp     al, [ebx]
    jne     @ssd_md5_fail
    inc     edi
    inc     ebx
    dec     ecx
    jnz     @ssd_md5cmp
    pop     ecx
    ;; Strong match! Send M marker with remote block index
    mov     byte ptr [marker], DELTA_MATCH
    mov     eax, [esi]          ; remote block index
    bswap   eax
    mov     dword ptr [marker + 1], eax
    invoke  ProtoSendMsg, pTlsCtx, CMD_SYNC_RESP, ADDR marker, 5
    jmp     @ssd_next_block

@ssd_md5_fail:
    pop     ecx
@ssd_next_sig:
    add     esi, 24
    inc     ecx
    jmp     @ssd_search

@ssd_no_match:
    ;; No match — send D marker with raw data
    mov     byte ptr [marker], DELTA_DATA
    mov     eax, dwRead
    bswap   eax
    mov     dword ptr [marker + 1], eax
    ;; Send marker header (5 bytes) + raw block data
    ;; Build combined buffer: [D][len_BE][data]
    mov     eax, dwRead
    add     eax, 5
    mov     cbDelta, eax
    invoke  GlobalAlloc, 0, cbDelta
    test    eax, eax
    jz      @ssd_close
    mov     pDeltaBuf, eax
    ;; Copy marker (5 bytes)
    invoke  RtlMoveMemory, pDeltaBuf, ADDR marker, 5
    ;; Copy data after marker
    mov     edi, pDeltaBuf
    add     edi, 5
    invoke  RtlMoveMemory, edi, ADDR blockBuf, dwRead
    invoke  ProtoSendMsg, pTlsCtx, CMD_SYNC_RESP, pDeltaBuf, cbDelta
    invoke  GlobalFree, pDeltaBuf

@ssd_next_block:
    inc     blockIdx
    jmp     @ssd_loop

@ssd_end:
    ;; Send E marker (end of delta)
    mov     byte ptr [marker], DELTA_END
    invoke  ProtoSendMsg, pTlsCtx, CMD_SYNC_RESP, ADDR marker, 1
    invoke  CloseHandle, hFile
    xor     eax, eax
    ret

@ssd_close:
    invoke  CloseHandle, hFile
@ssd_fail:
    mov     eax, -1
    ret
SyncSendDelta ENDP

;; =============================================================================
;; SyncHandleServer — Server-side: receive client sigs, send delta stream
;; Args: pTlsCtx, pFirstMsg (CMD_SYNC_REQ payload: encode_str(path) + u32be(sig_count) + sigs[24])
;; Returns: 0 = success
;; =============================================================================
SyncHandleServer PROC uses ebx esi edi \
    pTlsCtx:DWORD, pFirstMsg:DWORD

    LOCAL   nSigCount:DWORD
    LOCAL   pSigs:DWORD
    LOCAL   szPath[260]:BYTE

    ;; Parse payload: encode_str(path) + u32be(sig_count) + sigs[24 bytes each]
    mov     edx, pFirstMsg
    mov     esi, (MRSH_MSG PTR [edx]).pData

    ;; Decode path string (2-byte BE length + chars)
    movzx   eax, byte ptr [esi]
    shl     eax, 8
    movzx   ecx, byte ptr [esi + 1]
    or      eax, ecx                 ; eax = path length
    add     esi, 2                   ; esi = path string
    ;; Copy path to local buffer and null-terminate
    cmp     eax, 259
    jge     @shs_fail                ; path too long
    push    eax
    invoke  RtlMoveMemory, ADDR szPath, esi, eax
    pop     eax
    mov     byte ptr [szPath + eax], 0
    add     esi, eax                 ; advance past path string

    ;; Read sig_count (4-byte BE)
    mov     eax, [esi]
    bswap   eax
    mov     nSigCount, eax
    add     esi, 4                   ; esi = start of signature array
    mov     pSigs, esi

    ;; Call SyncSendDelta with server's file and client's signatures
    invoke  SyncSendDelta, pTlsCtx, ADDR szPath, pSigs, nSigCount
    ret

@shs_fail:
    ;; Send error
    invoke  ProtoSendError, pTlsCtx, ADDR _szFileNotFound
    mov     eax, -1
    ret
SyncHandleServer ENDP

;; =============================================================================
;; SyncApplyDelta — Client-side: receive M/D/E stream, reconstruct file
;; Args: pTlsCtx, lpLocalPath (existing local file), lpOutPath (output file)
;;       pLocalSigs (our computed sigs), nLocalSigCount
;; Receives CMD_SYNC_RESP messages until 'E' marker.
;; For 'M' markers: copies block from local file at given index.
;; For 'D' markers: writes new data directly.
;; Returns: 0 = success, -1 = error
;; =============================================================================
SyncApplyDelta PROC uses ebx esi edi \
    pTlsCtx:DWORD, lpLocalPath:DWORD, lpOutPath:DWORD, \
    pLocalSigs:DWORD, nLocalSigCount:DWORD

    LOCAL   hLocal:DWORD             ; source file (for M blocks)
    LOCAL   hOut:DWORD               ; output file
    LOCAL   msg:MRSH_MSG
    LOCAL   dwRead:DWORD
    LOCAL   dwWritten:DWORD
    LOCAL   blockBuf[SYNC_BLOCK_SIZE]:BYTE
    LOCAL   blockIdx:DWORD
    LOCAL   dataLen:DWORD

    ;; Open local file for reading (source of matched blocks)
    invoke  CreateFileA, lpLocalPath, GENERIC_READ, 1, \
            0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0
    cmp     eax, INVALID_HANDLE_VALUE
    je      @sad_fail
    mov     hLocal, eax

    ;; Create output file
    invoke  CreateFileA, lpOutPath, GENERIC_WRITE, 0, \
            0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0
    cmp     eax, INVALID_HANDLE_VALUE
    je      @sad_close_local
    mov     hOut, eax

@sad_loop:
    invoke  ProtoRecvMsg, pTlsCtx, ADDR msg
    test    eax, eax
    jnz     @sad_close_out
    cmp     msg.cmdId, CMD_SYNC_RESP
    jne     @sad_free_done

    ;; Check M/D/E marker (first byte of payload)
    cmp     msg.dataLen, 0
    je      @sad_free_loop
    mov     esi, msg.pData
    movzx   eax, byte ptr [esi]

    cmp     al, DELTA_END
    je      @sad_end
    cmp     al, DELTA_MATCH
    je      @sad_match
    cmp     al, DELTA_DATA
    je      @sad_data
    ;; Unknown marker — skip
    jmp     @sad_free_loop

@sad_match:
    ;; 'M' + u32be(block_index): copy block from local file
    cmp     msg.dataLen, 5
    jb      @sad_free_loop
    mov     eax, [esi + 1]
    bswap   eax
    mov     blockIdx, eax
    ;; Seek to block position in local file: index * SYNC_BLOCK_SIZE
    imul    eax, SYNC_BLOCK_SIZE
    invoke  SetFilePointer, hLocal, eax, 0, 0   ; FILE_BEGIN = 0
    ;; Read block from local file
    invoke  ReadFile, hLocal, ADDR blockBuf, SYNC_BLOCK_SIZE, ADDR dwRead, 0
    test    eax, eax
    jz      @sad_free_loop
    ;; Write to output
    invoke  WriteFile, hOut, ADDR blockBuf, dwRead, ADDR dwWritten, 0
    jmp     @sad_free_loop

@sad_data:
    ;; 'D' + u32be(data_length) + raw_data: write new data
    cmp     msg.dataLen, 5
    jb      @sad_free_loop
    mov     eax, [esi + 1]
    bswap   eax
    mov     dataLen, eax
    ;; Data starts at offset 5 in payload
    lea     edi, [esi + 5]
    invoke  WriteFile, hOut, edi, dataLen, ADDR dwWritten, 0
    jmp     @sad_free_loop

@sad_free_loop:
    invoke  ProtoFreeMsg, ADDR msg
    jmp     @sad_loop

@sad_end:
    invoke  ProtoFreeMsg, ADDR msg
    invoke  CloseHandle, hOut
    invoke  CloseHandle, hLocal
    xor     eax, eax
    ret

@sad_free_done:
    invoke  ProtoFreeMsg, ADDR msg
@sad_close_out:
    invoke  CloseHandle, hOut
@sad_close_local:
    invoke  CloseHandle, hLocal
@sad_fail:
    mov     eax, -1
    ret
SyncApplyDelta ENDP

;; =============================================================================
;; SyncHandlePush — Server-side: receive delta push from client
;; 1) Parse path from CMD_SYNC_PUSH
;; 2) Compute local file sigs, send as CMD_SYNC_SIGS
;; 3) Receive M/D/E stream (CMD_SYNC_DELTA), reconstruct file
;; =============================================================================
SyncHandlePush PROC uses ebx esi edi \
    pTlsCtx:DWORD, pMsg:DWORD

    LOCAL   szPath[260]:BYTE
    LOCAL   szTmp[280]:BYTE
    LOCAL   pSigs:DWORD
    LOCAL   nSigCount:DWORD
    LOCAL   hLocal:DWORD
    LOCAL   hOut:DWORD
    LOCAL   msg2:MRSH_MSG
    LOCAL   dwRead:DWORD
    LOCAL   dwWritten:DWORD
    LOCAL   blockBuf[SYNC_BLOCK_SIZE]:BYTE
    LOCAL   blockIdx:DWORD
    LOCAL   dataLen:DWORD

    ;; Parse path from CMD_SYNC_PUSH payload: encode_str(path)
    mov     edx, pMsg
    mov     esi, (MRSH_MSG PTR [edx]).pData
    movzx   eax, byte ptr [esi]
    shl     eax, 8
    movzx   ecx, byte ptr [esi + 1]
    or      eax, ecx
    add     esi, 2
    cmp     eax, 259
    jge     @shp_fail
    push    eax
    invoke  RtlMoveMemory, ADDR szPath, esi, eax
    pop     eax
    mov     byte ptr [szPath + eax], 0

    ;; Compute local sigs (returns empty if file doesn't exist)
    invoke  SyncComputeSignatures, ADDR szPath, ADDR pSigs, ADDR nSigCount

    ;; Send sigs as CMD_SYNC_SIGS: u32be(sig_count) + sigs[24 bytes each]
    mov     eax, nSigCount
    imul    eax, 24
    add     eax, 4                  ; 4 bytes for count
    mov     ebx, eax                ; total payload size
    invoke  GlobalAlloc, 0, ebx
    test    eax, eax
    jz      @shp_free_sigs
    mov     edi, eax
    push    edi                     ; save pPayload
    ;; Write sig count (4-byte BE)
    mov     eax, nSigCount
    bswap   eax
    mov     [edi], eax
    add     edi, 4
    ;; Copy sig array
    cmp     nSigCount, 0
    je      @shp_send_sigs
    mov     eax, nSigCount
    imul    eax, 24
    invoke  RtlMoveMemory, edi, pSigs, eax
@shp_send_sigs:
    pop     edi                     ; pPayload
    invoke  ProtoSendMsg, pTlsCtx, CMD_SYNC_SIGS, edi, ebx
    invoke  GlobalFree, edi

    ;; Free local sigs
    cmp     pSigs, 0
    je      @shp_recv_delta
    invoke  GlobalFree, pSigs

@shp_recv_delta:
    ;; Now receive M/D/E stream from client
    ;; Open existing file for reading (source of M blocks)
    invoke  CreateFileA, ADDR szPath, GENERIC_READ, 1, \
            0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0
    cmp     eax, INVALID_HANDLE_VALUE
    je      @shp_no_local
    mov     hLocal, eax
    jmp     @shp_open_tmp
@shp_no_local:
    mov     hLocal, 0               ; no local file (all D blocks)

@shp_open_tmp:
    ;; Write to temp file
    invoke  wsprintfA, ADDR szTmp, ADDR _szSyncTmpFmt, ADDR szPath
    invoke  CreateFileA, ADDR szTmp, GENERIC_WRITE, 0, \
            0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0
    cmp     eax, INVALID_HANDLE_VALUE
    je      @shp_close_local
    mov     hOut, eax

@shp_delta_loop:
    invoke  ProtoRecvMsg, pTlsCtx, ADDR msg2
    test    eax, eax
    jnz     @shp_close_out
    cmp     msg2.cmdId, CMD_SYNC_DELTA
    jne     @shp_free_done

    cmp     msg2.dataLen, 0
    je      @shp_free_loop
    mov     esi, msg2.pData
    movzx   eax, byte ptr [esi]

    cmp     al, DELTA_END
    je      @shp_end
    cmp     al, DELTA_MATCH
    je      @shp_match
    cmp     al, DELTA_DATA
    je      @shp_data
    jmp     @shp_free_loop

@shp_match:
    cmp     msg2.dataLen, 5
    jb      @shp_free_loop
    cmp     hLocal, 0
    je      @shp_free_loop          ; no local file, skip M
    mov     eax, [esi + 1]
    bswap   eax
    imul    eax, SYNC_BLOCK_SIZE
    invoke  SetFilePointer, hLocal, eax, 0, 0
    invoke  ReadFile, hLocal, ADDR blockBuf, SYNC_BLOCK_SIZE, ADDR dwRead, 0
    test    eax, eax
    jz      @shp_free_loop
    invoke  WriteFile, hOut, ADDR blockBuf, dwRead, ADDR dwWritten, 0
    jmp     @shp_free_loop

@shp_data:
    cmp     msg2.dataLen, 5
    jb      @shp_free_loop
    mov     eax, [esi + 1]
    bswap   eax
    mov     dataLen, eax
    lea     edi, [esi + 5]
    invoke  WriteFile, hOut, edi, dataLen, ADDR dwWritten, 0
    jmp     @shp_free_loop

@shp_free_loop:
    invoke  ProtoFreeMsg, ADDR msg2
    jmp     @shp_delta_loop

@shp_end:
    invoke  ProtoFreeMsg, ADDR msg2
    invoke  CloseHandle, hOut
    cmp     hLocal, 0
    je      @shp_rename
    invoke  CloseHandle, hLocal
@shp_rename:
    ;; Rename temp → target
    invoke  MoveFileExA, ADDR szTmp, ADDR szPath, 1
    ;; Send CMD_SYNC_DONE
    invoke  ProtoSendMsg, pTlsCtx, CMD_SYNC_DONE, 0, 0
    xor     eax, eax
    ret

@shp_free_done:
    invoke  ProtoFreeMsg, ADDR msg2
@shp_close_out:
    invoke  CloseHandle, hOut
    invoke  DeleteFileA, ADDR szTmp
@shp_close_local:
    cmp     hLocal, 0
    je      @shp_fail
    invoke  CloseHandle, hLocal
@shp_free_sigs:
    cmp     pSigs, 0
    je      @shp_fail
    invoke  GlobalFree, pSigs
@shp_fail:
    invoke  ProtoSendError, pTlsCtx, ADDR _szFileNotFound
    mov     eax, -1
    ret
SyncHandlePush ENDP
