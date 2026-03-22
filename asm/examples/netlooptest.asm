;; netlooptest.asm — Net loopback test: listen→connect→send→recv→close
.686
.model flat, stdcall
option casemap:none

NULL equ 0
include net.inc

ExitProcess     PROTO :DWORD
GetStdHandle    PROTO :DWORD
WriteFile       PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
CreateThread    PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
Sleep           PROTO :DWORD
lstrlenA        PROTO :DWORD
lstrcmpA        PROTO :DWORD, :DWORD
wsprintfA       PROTO C :DWORD, :DWORD, :VARARG

STD_OUTPUT_HANDLE equ -11
TEST_PORT       equ 19876

.data
    szT1    db "[1] NetInit:       ", 0
    szT2    db "[2] NetListen:     ", 0
    szT3    db "[3] Connect+Accept:", 0
    szT4    db "[4] Send+Recv:     ", 0
    szT5    db "[5] LenPrefixed:   ", 0
    szT6    db "[6] NetClose:      ", 0
    szOk    db "OK", 13, 10, 0
    szFail  db "FAIL", 13, 10, 0
    szDbg   db "  result=%d", 13, 10, 0

    szTestMsg   db "hello-from-asm-nettest", 0
    szLenMsg    db "length-prefixed-payload", 0
    szLocal     db "127.0.0.1", 0

.data?
    hOut        DWORD ?
    nWr         DWORD ?
    listenSock  DWORD ?
    serverSock  DWORD ?
    clientSock  DWORD ?
    recvBuf     BYTE 256 dup(?)
    pLenBuf     DWORD ?
    nLenBuf     DWORD ?
    msgBuf      BYTE 256 dup(?)

.code

Print PROC lpStr:DWORD
    invoke lstrlenA, lpStr
    invoke WriteFile, hOut, lpStr, eax, ADDR nWr, 0
    ret
Print ENDP

;; Server thread: accept one connection, recv, send back, close
_ServerThread PROC lpParam:DWORD
    ;; Accept
    invoke NetAccept, listenSock
    mov    serverSock, eax
    ;; Recv
    invoke NetRecv, serverSock, ADDR recvBuf, 256
    ;; Send back same data
    invoke NetSendAll, serverSock, ADDR recvBuf, eax
    ;; Also test len-prefixed
    invoke lstrlenA, ADDR szLenMsg
    invoke NetSendLenPrefixed, serverSock, ADDR szLenMsg, eax
    ;; Close
    invoke NetClose, serverSock
    ret
_ServerThread ENDP

start:
    invoke GetStdHandle, STD_OUTPUT_HANDLE
    mov    hOut, eax

    ;; T1: Init
    invoke Print, ADDR szT1
    invoke NetInit
    mov    ebx, eax
    test   ebx, ebx
    jnz    @t1f
    invoke Print, ADDR szOk
    jmp    @t2
@t1f:
    invoke Print, ADDR szFail
    jmp    @done

    ;; T2: Listen
@t2:
    invoke Print, ADDR szT2
    invoke NetListen, TEST_PORT, 1
    cmp    eax, INVALID_SOCKET
    je     @t2f
    mov    listenSock, eax
    invoke Print, ADDR szOk
    jmp    @t3
@t2f:
    invoke Print, ADDR szFail
    jmp    @cleanup

    ;; T3: Start server thread, connect client
@t3:
    invoke Print, ADDR szT3
    invoke CreateThread, 0, 0, ADDR _ServerThread, 0, 0, 0
    invoke Sleep, 100   ; let server thread start
    invoke NetConnect, ADDR szLocal, TEST_PORT
    cmp    eax, INVALID_SOCKET
    je     @t3f
    mov    clientSock, eax
    invoke Print, ADDR szOk
    jmp    @t4
@t3f:
    invoke Print, ADDR szFail
    jmp    @close_listen

    ;; T4: Send message, recv echo (exact length to avoid TCP coalescing)
@t4:
    invoke Print, ADDR szT4
    invoke lstrlenA, ADDR szTestMsg
    mov    ebx, eax             ; save length
    invoke NetSendAll, clientSock, ADDR szTestMsg, ebx
    invoke Sleep, 200           ; let server echo
    invoke NetRecvAll, clientSock, ADDR recvBuf, ebx
    test   eax, eax
    jnz    @t4f
    ;; Null-terminate at exact length
    mov    byte ptr [recvBuf + ebx], 0
    invoke lstrcmpA, ADDR recvBuf, ADDR szTestMsg
    test   eax, eax
    jnz    @t4f
    invoke Print, ADDR szOk
    jmp    @t5
@t4f:
    invoke Print, ADDR szFail

    ;; T5: Recv len-prefixed message
@t5:
    invoke Print, ADDR szT5
    invoke Sleep, 100
    invoke NetRecvLenPrefixed, clientSock, ADDR pLenBuf, ADDR nLenBuf
    test   eax, eax
    jnz    @t5f
    ;; Null-terminate and compare
    mov    edx, pLenBuf
    mov    ecx, nLenBuf
    mov    byte ptr [edx + ecx], 0
    invoke lstrcmpA, pLenBuf, ADDR szLenMsg
    test   eax, eax
    jnz    @t5f
    invoke GlobalFree, pLenBuf
    invoke Print, ADDR szOk
    jmp    @t6
@t5f:
    invoke Print, ADDR szFail

    ;; T6: Close
@t6:
    invoke Print, ADDR szT6
    invoke NetClose, clientSock
    invoke Print, ADDR szOk

@close_listen:
    invoke NetClose, listenSock
@cleanup:
    invoke NetCleanup
@done:
    invoke ExitProcess, 0
end start
