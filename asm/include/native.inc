;; =============================================================================
;; native.inc — Native system commands: ps, kill
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; Uses Toolhelp32 for process enumeration, OpenProcess/TerminateProcess for kill.
;; Sub-commands via CMD_NATIVE: ps=0x01, kill=0x02
;; =============================================================================

;; ---- Sub-command IDs ----
NATIVE_PS           equ 01h
NATIVE_KILL         equ 02h

;; ---- Toolhelp32 API ----
CreateToolhelp32Snapshot PROTO :DWORD, :DWORD
Process32First      PROTO :DWORD, :DWORD
Process32Next       PROTO :DWORD, :DWORD
OpenProcess         PROTO :DWORD, :DWORD, :DWORD
TerminateProcess    PROTO :DWORD, :DWORD

TH32CS_SNAPPROCESS  equ 02h
MAX_PATH            equ 260
PROCESS_TERMINATE   equ 0001h

;; ---- PROCESSENTRY32 structure ----
PROCESSENTRY32 STRUCT
    dwSize              DWORD ?
    cntUsage            DWORD ?
    th32ProcessID       DWORD ?
    th32DefaultHeapID   DWORD ?
    th32ModuleID        DWORD ?
    cntThreads          DWORD ?
    th32ParentProcessID DWORD ?
    pcPriClassBase      DWORD ?     ; LONG
    dwFlags             DWORD ?
    szExeFile           BYTE MAX_PATH dup(?)
PROCESSENTRY32 ENDS

wsprintfA   PROTO C :DWORD, :DWORD, :VARARG
lstrlenA    PROTO :DWORD
lstrcatA    PROTO :DWORD, :DWORD

IFNDEF _GLOBALALLOC_DEFINED
_GLOBALALLOC_DEFINED equ 1
GlobalAlloc     PROTO :DWORD, :DWORD
GlobalFree      PROTO :DWORD
ENDIF

.data
    ;; JSON format for each process entry
    _szPsFmt    db '{"pid":%d,"name":"%s","threads":%d}', 0
    _szPsSep    db ",", 0
    _szPsOpen   db "[", 0
    _szPsClose  db "]", 0
    _szKillOk   db "killed", 0
    _szKillFail db "kill failed", 0

;; Forward declarations
_NativePs   PROTO :DWORD
_NativeKill PROTO :DWORD, :DWORD

.code

;; =============================================================================
;; NativeHandleServer — Dispatch native sub-commands
;; Args: pTlsCtx, pMsg (CMD_NATIVE message)
;; Payload: sub_cmd(1) + data
;; Returns: 0
;; =============================================================================
NativeHandleServer PROC uses ebx esi edi \
    pTlsCtx:DWORD, pMsg:DWORD

    mov     edx, pMsg
    cmp     (MRSH_MSG PTR [edx]).dataLen, 0
    je      @nhs_err
    mov     esi, (MRSH_MSG PTR [edx]).pData
    movzx   eax, byte ptr [esi]

    cmp     al, NATIVE_PS
    je      @nhs_ps
    cmp     al, NATIVE_KILL
    je      @nhs_kill
    jmp     @nhs_err

@nhs_ps:
    invoke  _NativePs, pTlsCtx
    ret

@nhs_kill:
    ;; Payload: sub_cmd(1) + u32be(pid)
    mov     edx, pMsg
    cmp     (MRSH_MSG PTR [edx]).dataLen, 5
    jb      @nhs_err
    mov     eax, [esi + 1]
    bswap   eax
    invoke  _NativeKill, pTlsCtx, eax
    ret

@nhs_err:
    invoke  ProtoSendError, pTlsCtx, ADDR _szKillFail
    mov     eax, -1
    ret
NativeHandleServer ENDP

;; =============================================================================
;; _NativePs — Enumerate processes, send JSON array
;; =============================================================================
_NativePs PROC uses ebx esi edi pTlsCtx:DWORD
    LOCAL   pe:PROCESSENTRY32
    LOCAL   hSnap:DWORD
    LOCAL   pBuf:DWORD
    LOCAL   cbBuf:DWORD
    LOCAL   cbUsed:DWORD
    LOCAL   szEntry[512]:BYTE

    ;; Allocate output buffer (64KB should be enough for process list)
    mov     cbBuf, 65536
    invoke  GlobalAlloc, 0, cbBuf
    test    eax, eax
    jz      @nps_fail
    mov     pBuf, eax
    mov     cbUsed, 0

    ;; Start with "["
    mov     edi, pBuf
    mov     byte ptr [edi], '['
    mov     cbUsed, 1

    ;; Create snapshot
    invoke  CreateToolhelp32Snapshot, TH32CS_SNAPPROCESS, 0
    cmp     eax, INVALID_HANDLE_VALUE
    je      @nps_free
    mov     hSnap, eax

    ;; First process
    mov     pe.dwSize, SIZEOF PROCESSENTRY32
    invoke  Process32First, hSnap, ADDR pe
    test    eax, eax
    jz      @nps_close
    xor     ebx, ebx                ; entry counter

@nps_loop:
    ;; Format JSON entry
    cmp     ebx, 0
    je      @nps_no_comma
    ;; Add comma separator
    mov     edi, pBuf
    add     edi, cbUsed
    mov     byte ptr [edi], ','
    inc     cbUsed
@nps_no_comma:
    invoke  wsprintfA, ADDR szEntry, ADDR _szPsFmt, \
            pe.th32ProcessID, ADDR pe.szExeFile, pe.cntThreads
    invoke  lstrlenA, ADDR szEntry
    mov     ecx, eax

    ;; Check buffer space
    mov     eax, cbUsed
    add     eax, ecx
    add     eax, 2                  ; room for "]" + null
    cmp     eax, cbBuf
    jge     @nps_close              ; buffer full, send what we have

    ;; Copy entry to buffer
    mov     edi, pBuf
    add     edi, cbUsed
    invoke  RtlMoveMemory, edi, ADDR szEntry, ecx
    add     cbUsed, ecx
    inc     ebx

    ;; Next process
    invoke  Process32Next, hSnap, ADDR pe
    test    eax, eax
    jnz     @nps_loop

@nps_close:
    invoke  CloseHandle, hSnap

    ;; Close array "]"
    mov     edi, pBuf
    add     edi, cbUsed
    mov     byte ptr [edi], ']'
    inc     cbUsed

    ;; Send response
    invoke  ProtoSendMsg, pTlsCtx, CMD_NATIVE_RESP, pBuf, cbUsed
    invoke  GlobalFree, pBuf
    xor     eax, eax
    ret

@nps_free:
    invoke  GlobalFree, pBuf
@nps_fail:
    invoke  ProtoSendError, pTlsCtx, ADDR _szKillFail
    mov     eax, -1
    ret
_NativePs ENDP

;; =============================================================================
;; _NativeKill — Terminate process by PID
;; =============================================================================
_NativeKill PROC pTlsCtx:DWORD, dwPid:DWORD
    LOCAL   hProc:DWORD

    invoke  OpenProcess, PROCESS_TERMINATE, 0, dwPid
    test    eax, eax
    jz      @nk_fail
    mov     hProc, eax

    invoke  TerminateProcess, hProc, 1
    push    eax
    invoke  CloseHandle, hProc
    pop     eax
    test    eax, eax
    jz      @nk_fail

    ;; Send success
    invoke  lstrlenA, ADDR _szKillOk
    invoke  ProtoSendMsg, pTlsCtx, CMD_NATIVE_RESP, ADDR _szKillOk, eax
    xor     eax, eax
    ret

@nk_fail:
    invoke  ProtoSendError, pTlsCtx, ADDR _szKillFail
    mov     eax, -1
    ret
_NativeKill ENDP
