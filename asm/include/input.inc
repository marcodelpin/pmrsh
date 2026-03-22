;; =============================================================================
;; input.inc — GUI automation: mouse, keyboard, window management
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; Uses SendInput for mouse/keyboard, EnumWindows for window ops.
;; Sub-commands via CMD_INPUT:
;;   Mouse:  pos=0x01, move=0x02, click=0x03, scroll=0x04
;;   Key:    type=0x05, tap=0x06
;;   Window: list=0x07, find=0x08, activate=0x09, close=0x0A
;; =============================================================================

;; ---- Sub-command IDs ----
INPUT_MOUSE_POS     equ 01h
INPUT_MOUSE_MOVE    equ 02h
INPUT_MOUSE_CLICK   equ 03h
INPUT_MOUSE_SCROLL  equ 04h
INPUT_KEY_TYPE      equ 05h
INPUT_KEY_TAP       equ 06h
INPUT_WIN_LIST      equ 07h
INPUT_WIN_FIND      equ 08h
INPUT_WIN_ACTIVATE  equ 09h
INPUT_WIN_CLOSE     equ 0Ah

;; ---- Win32 API ----
SendInput           PROTO :DWORD, :DWORD, :DWORD
GetCursorPos        PROTO :DWORD
SetCursorPos        PROTO :DWORD, :DWORD
EnumWindows         PROTO :DWORD, :DWORD
GetWindowTextA      PROTO :DWORD, :DWORD, :DWORD
IsWindowVisible     PROTO :DWORD
SetForegroundWindow PROTO :DWORD
ShowWindow          PROTO :DWORD, :DWORD
PostMessageA        PROTO :DWORD, :DWORD, :DWORD, :DWORD
GetWindowThreadProcessId PROTO :DWORD, :DWORD
GetWindowRect       PROTO :DWORD, :DWORD
MapVirtualKeyA      PROTO :DWORD, :DWORD
StrStrIA            PROTO :DWORD, :DWORD

;; ---- Constants ----
INPUT_MOUSE         equ 0
INPUT_KEYBOARD      equ 1
MOUSEEVENTF_LEFTDOWN  equ 0002h
MOUSEEVENTF_LEFTUP    equ 0004h
MOUSEEVENTF_WHEEL     equ 0800h
KEYEVENTF_KEYUP       equ 0002h
KEYEVENTF_UNICODE     equ 0004h
WM_CLOSE            equ 0010h
SW_RESTORE          equ 9

;; ---- INPUT structure for SendInput ----
;; Mouse input: type(4) + dx(4) + dy(4) + mouseData(4) + dwFlags(4) + time(4) + dwExtraInfo(4) = 28
;; Keyboard: type(4) + wVk(2) + wScan(2) + dwFlags(4) + time(4) + dwExtraInfo(4) = 20
;; Total INPUT union size = 28 bytes
SIZEOF_INPUT        equ 28

wsprintfA   PROTO C :DWORD, :DWORD, :VARARG
lstrlenA    PROTO :DWORD
lstrcmpiA   PROTO :DWORD, :DWORD

IFNDEF _GLOBALALLOC_DEFINED
_GLOBALALLOC_DEFINED equ 1
GlobalAlloc     PROTO :DWORD, :DWORD
GlobalFree      PROTO :DWORD
ENDIF
IFNDEF _RTLZEROMEMORY_DEFINED
_RTLZEROMEMORY_DEFINED equ 1
RtlZeroMemory   PROTO :DWORD, :DWORD
ENDIF

;; Forward declarations for callbacks and helpers
_WinListCallback PROTO :DWORD, :DWORD
_WinFindCallback PROTO :DWORD, :DWORD
_LookupVK        PROTO :DWORD

POINT STRUCT
    x   DWORD ?
    y   DWORD ?
POINT ENDS

RECT STRUCT
    left    DWORD ?
    top     DWORD ?
    right   DWORD ?
    bottom  DWORD ?
RECT ENDS

.data
    _szPosFmt   db "%d,%d", 0
    _szWinFmt   db '{"hwnd":%u,"title":"%s","pid":%u,"x":%d,"y":%d,"w":%d,"h":%d}', 0
    _szInputOk  db "ok", 0
    _szInputErr db "input failed", 0
    ;; VK code table for named keys
    _szKeyEnter db "enter", 0
    _szKeyEsc   db "esc", 0
    _szKeyTab   db "tab", 0
    _szKeyBack  db "backspace", 0
    _szKeyDel   db "delete", 0
    _szKeyUp    db "up", 0
    _szKeyDown  db "down", 0
    _szKeyLeft  db "left", 0
    _szKeyRight db "right", 0
    _szKeyHome  db "home", 0
    _szKeyEnd   db "end", 0
    _szKeyPgUp  db "pageup", 0
    _szKeyPgDn  db "pagedown", 0
    _szKeyF1    db "f1", 0
    _szKeyF2    db "f2", 0
    _szKeyF3    db "f3", 0
    _szKeyF4    db "f4", 0
    _szKeyF5    db "f5", 0
    _szKeySpace db "space", 0

.data?
    _inputBuf   BYTE SIZEOF_INPUT * 4 dup(?)    ; up to 4 input events
    _winListBuf BYTE 65536 dup(?)
    _winListOff DWORD ?
    _winFindPat DWORD ?     ; ptr to search pattern for find callback
    _winTitleBuf BYTE 256 dup(?)

.code

;; =============================================================================
;; InputHandleServer — Dispatch GUI input sub-commands
;; =============================================================================
InputHandleServer PROC uses ebx esi edi \
    pTlsCtx:DWORD, pMsg:DWORD

    LOCAL   pt:POINT
    LOCAL   szPos[32]:BYTE

    mov     edx, pMsg
    cmp     (MRSH_MSG PTR [edx]).dataLen, 0
    je      @ihs_err
    mov     esi, (MRSH_MSG PTR [edx]).pData
    movzx   eax, byte ptr [esi]

    cmp     al, INPUT_MOUSE_POS
    je      @ihs_mpos
    cmp     al, INPUT_MOUSE_MOVE
    je      @ihs_mmove
    cmp     al, INPUT_MOUSE_CLICK
    je      @ihs_mclick
    cmp     al, INPUT_MOUSE_SCROLL
    je      @ihs_mscroll
    cmp     al, INPUT_KEY_TYPE
    je      @ihs_ktype
    cmp     al, INPUT_KEY_TAP
    je      @ihs_ktap
    cmp     al, INPUT_WIN_LIST
    je      @ihs_wlist
    cmp     al, INPUT_WIN_FIND
    je      @ihs_wfind
    cmp     al, INPUT_WIN_ACTIVATE
    je      @ihs_wact
    cmp     al, INPUT_WIN_CLOSE
    je      @ihs_wclose
    jmp     @ihs_err

;; ---- Mouse position ----
@ihs_mpos:
    invoke  GetCursorPos, ADDR pt
    invoke  wsprintfA, ADDR szPos, ADDR _szPosFmt, pt.x, pt.y
    invoke  lstrlenA, ADDR szPos
    invoke  ProtoSendMsg, pTlsCtx, CMD_INPUT_RESP, ADDR szPos, eax
    xor     eax, eax
    ret

;; ---- Mouse move ----
@ihs_mmove:
    ;; Payload: sub_cmd(1) + i32be(x) + i32be(y)
    mov     edx, pMsg
    cmp     (MRSH_MSG PTR [edx]).dataLen, 9
    jb      @ihs_err
    mov     eax, [esi + 1]
    bswap   eax
    mov     ebx, eax                ; x
    mov     eax, [esi + 5]
    bswap   eax                     ; y
    invoke  SetCursorPos, ebx, eax
    invoke  ProtoSendMsg, pTlsCtx, CMD_INPUT_RESP, ADDR _szInputOk, 2
    xor     eax, eax
    ret

;; ---- Mouse click ----
@ihs_mclick:
    invoke  RtlZeroMemory, ADDR _inputBuf, SIZEOF_INPUT * 2
    ;; Mouse down
    mov     dword ptr [_inputBuf], INPUT_MOUSE       ; type = mouse
    mov     dword ptr [_inputBuf + 16], MOUSEEVENTF_LEFTDOWN  ; dwFlags offset = 16
    ;; Mouse up
    mov     dword ptr [_inputBuf + SIZEOF_INPUT], INPUT_MOUSE
    mov     dword ptr [_inputBuf + SIZEOF_INPUT + 16], MOUSEEVENTF_LEFTUP
    invoke  SendInput, 2, ADDR _inputBuf, SIZEOF_INPUT
    invoke  ProtoSendMsg, pTlsCtx, CMD_INPUT_RESP, ADDR _szInputOk, 2
    xor     eax, eax
    ret

;; ---- Mouse scroll ----
@ihs_mscroll:
    ;; Payload: sub_cmd(1) + i32be(delta)
    mov     edx, pMsg
    cmp     (MRSH_MSG PTR [edx]).dataLen, 5
    jb      @ihs_err
    mov     eax, [esi + 1]
    bswap   eax
    push    eax                     ; save delta
    invoke  RtlZeroMemory, ADDR _inputBuf, SIZEOF_INPUT
    mov     dword ptr [_inputBuf], INPUT_MOUSE
    pop     eax
    mov     dword ptr [_inputBuf + 12], eax          ; mouseData = delta
    mov     dword ptr [_inputBuf + 16], MOUSEEVENTF_WHEEL
    invoke  SendInput, 1, ADDR _inputBuf, SIZEOF_INPUT
    invoke  ProtoSendMsg, pTlsCtx, CMD_INPUT_RESP, ADDR _szInputOk, 2
    xor     eax, eax
    ret

;; ---- Key type (unicode text) ----
@ihs_ktype:
    ;; Payload: sub_cmd(1) + text bytes (ASCII/UTF-8)
    mov     edx, pMsg
    mov     ecx, (MRSH_MSG PTR [edx]).dataLen
    dec     ecx                     ; skip sub_cmd byte
    cmp     ecx, 0
    jle     @ihs_err
    lea     edi, [esi + 1]          ; text start
    ;; Send each char as unicode key event (down+up)
@ihs_ktype_loop:
    cmp     ecx, 0
    jle     @ihs_ktype_done
    push    ecx
    push    edi
    movzx   eax, byte ptr [edi]
    invoke  RtlZeroMemory, ADDR _inputBuf, SIZEOF_INPUT * 2
    ;; Key down
    mov     dword ptr [_inputBuf], INPUT_KEYBOARD     ; type
    movzx   eax, byte ptr [edi]
    mov     word ptr [_inputBuf + 6], ax              ; wScan = char
    mov     dword ptr [_inputBuf + 8], KEYEVENTF_UNICODE  ; dwFlags
    ;; Key up
    mov     dword ptr [_inputBuf + SIZEOF_INPUT], INPUT_KEYBOARD
    mov     word ptr [_inputBuf + SIZEOF_INPUT + 6], ax
    mov     dword ptr [_inputBuf + SIZEOF_INPUT + 8], KEYEVENTF_UNICODE or KEYEVENTF_KEYUP
    invoke  SendInput, 2, ADDR _inputBuf, SIZEOF_INPUT
    pop     edi
    pop     ecx
    inc     edi
    dec     ecx
    jmp     @ihs_ktype_loop
@ihs_ktype_done:
    invoke  ProtoSendMsg, pTlsCtx, CMD_INPUT_RESP, ADDR _szInputOk, 2
    xor     eax, eax
    ret

;; ---- Key tap (named key) ----
@ihs_ktap:
    ;; Payload: sub_cmd(1) + encode_str(key_name)
    mov     edx, pMsg
    cmp     (MRSH_MSG PTR [edx]).dataLen, 3
    jb      @ihs_err
    ;; Decode key name
    movzx   eax, byte ptr [esi + 1]
    shl     eax, 8
    movzx   ecx, byte ptr [esi + 2]
    or      eax, ecx
    lea     edi, [esi + 3]
    mov     byte ptr [edi + eax], 0 ; null-terminate

    ;; Lookup VK code from name
    invoke  _LookupVK, edi
    test    eax, eax
    jz      @ihs_err
    ;; Send key down + up
    push    eax
    invoke  RtlZeroMemory, ADDR _inputBuf, SIZEOF_INPUT * 2
    pop     eax
    mov     dword ptr [_inputBuf], INPUT_KEYBOARD
    mov     word ptr [_inputBuf + 4], ax              ; wVk
    mov     dword ptr [_inputBuf + SIZEOF_INPUT], INPUT_KEYBOARD
    mov     word ptr [_inputBuf + SIZEOF_INPUT + 4], ax
    mov     dword ptr [_inputBuf + SIZEOF_INPUT + 8], KEYEVENTF_KEYUP
    invoke  SendInput, 2, ADDR _inputBuf, SIZEOF_INPUT
    invoke  ProtoSendMsg, pTlsCtx, CMD_INPUT_RESP, ADDR _szInputOk, 2
    xor     eax, eax
    ret

;; ---- Window list ----
@ihs_wlist:
    ;; Build JSON array of visible windows
    mov     _winListOff, 0
    mov     byte ptr [_winListBuf], '['
    mov     _winListOff, 1
    invoke  EnumWindows, ADDR _WinListCallback, 0
    ;; Close array
    mov     edi, OFFSET _winListBuf
    add     edi, _winListOff
    mov     byte ptr [edi], ']'
    inc     _winListOff
    invoke  ProtoSendMsg, pTlsCtx, CMD_INPUT_RESP, ADDR _winListBuf, _winListOff
    xor     eax, eax
    ret

;; ---- Window find ----
@ihs_wfind:
    ;; Payload: sub_cmd(1) + encode_str(pattern)
    mov     edx, pMsg
    cmp     (MRSH_MSG PTR [edx]).dataLen, 3
    jb      @ihs_err
    movzx   eax, byte ptr [esi + 1]
    shl     eax, 8
    movzx   ecx, byte ptr [esi + 2]
    or      eax, ecx
    lea     edi, [esi + 3]
    mov     byte ptr [edi + eax], 0
    mov     _winFindPat, edi
    ;; Enumerate with filter
    mov     _winListOff, 0
    mov     byte ptr [_winListBuf], '['
    mov     _winListOff, 1
    invoke  EnumWindows, ADDR _WinFindCallback, 0
    mov     edi, OFFSET _winListBuf
    add     edi, _winListOff
    mov     byte ptr [edi], ']'
    inc     _winListOff
    invoke  ProtoSendMsg, pTlsCtx, CMD_INPUT_RESP, ADDR _winListBuf, _winListOff
    xor     eax, eax
    ret

;; ---- Window activate ----
@ihs_wact:
    ;; Payload: sub_cmd(1) + u32be(hwnd)
    mov     edx, pMsg
    cmp     (MRSH_MSG PTR [edx]).dataLen, 5
    jb      @ihs_err
    mov     eax, [esi + 1]
    bswap   eax
    push    eax
    invoke  ShowWindow, eax, SW_RESTORE
    pop     eax
    invoke  SetForegroundWindow, eax
    invoke  ProtoSendMsg, pTlsCtx, CMD_INPUT_RESP, ADDR _szInputOk, 2
    xor     eax, eax
    ret

;; ---- Window close ----
@ihs_wclose:
    ;; Payload: sub_cmd(1) + u32be(hwnd)
    mov     edx, pMsg
    cmp     (MRSH_MSG PTR [edx]).dataLen, 5
    jb      @ihs_err
    mov     eax, [esi + 1]
    bswap   eax
    invoke  PostMessageA, eax, WM_CLOSE, 0, 0
    invoke  ProtoSendMsg, pTlsCtx, CMD_INPUT_RESP, ADDR _szInputOk, 2
    xor     eax, eax
    ret

@ihs_err:
    invoke  ProtoSendError, pTlsCtx, ADDR _szInputErr
    mov     eax, -1
    ret
InputHandleServer ENDP

;; =============================================================================
;; _WinListCallback — EnumWindows callback: add visible windows to JSON array
;; =============================================================================
_WinListCallback PROC hWnd:DWORD, lParam:DWORD
    LOCAL   dwPid:DWORD
    LOCAL   rc:RECT
    LOCAL   szEntry[512]:BYTE

    invoke  IsWindowVisible, hWnd
    test    eax, eax
    jz      @wlc_next
    invoke  GetWindowTextA, hWnd, ADDR _winTitleBuf, 255
    test    eax, eax
    jz      @wlc_next
    invoke  GetWindowThreadProcessId, hWnd, ADDR dwPid
    invoke  GetWindowRect, hWnd, ADDR rc
    ;; Compute width/height
    mov     eax, rc.right
    sub     eax, rc.left            ; width
    mov     ecx, rc.bottom
    sub     ecx, rc.top             ; height
    ;; Format JSON
    invoke  wsprintfA, ADDR szEntry, ADDR _szWinFmt, \
            hWnd, ADDR _winTitleBuf, dwPid, rc.left, rc.top, eax, ecx
    invoke  lstrlenA, ADDR szEntry
    mov     ecx, eax
    ;; Check buffer space
    mov     eax, _winListOff
    add     eax, ecx
    add     eax, 2
    cmp     eax, 65000
    jge     @wlc_stop
    ;; Add comma if not first
    cmp     _winListOff, 1
    je      @wlc_no_comma
    mov     edi, OFFSET _winListBuf
    add     edi, _winListOff
    mov     byte ptr [edi], ','
    inc     _winListOff
@wlc_no_comma:
    mov     edi, OFFSET _winListBuf
    add     edi, _winListOff
    invoke  RtlMoveMemory, edi, ADDR szEntry, ecx
    add     _winListOff, ecx
@wlc_next:
    mov     eax, 1                  ; continue enumeration
    ret
@wlc_stop:
    xor     eax, eax                ; stop enumeration
    ret
_WinListCallback ENDP

;; =============================================================================
;; _WinFindCallback — EnumWindows callback: filter by title pattern
;; =============================================================================
_WinFindCallback PROC hWnd:DWORD, lParam:DWORD
    LOCAL   dwPid:DWORD
    LOCAL   rc:RECT
    LOCAL   szEntry[512]:BYTE

    invoke  IsWindowVisible, hWnd
    test    eax, eax
    jz      @wfc_next
    invoke  GetWindowTextA, hWnd, ADDR _winTitleBuf, 255
    test    eax, eax
    jz      @wfc_next
    ;; Case-insensitive substring search using StrStrIA
    invoke  StrStrIA, ADDR _winTitleBuf, _winFindPat
    test    eax, eax
    jz      @wfc_next
    ;; Match — add to list (same as _WinListCallback)
    invoke  GetWindowThreadProcessId, hWnd, ADDR dwPid
    invoke  GetWindowRect, hWnd, ADDR rc
    mov     eax, rc.right
    sub     eax, rc.left
    mov     ecx, rc.bottom
    sub     ecx, rc.top
    invoke  wsprintfA, ADDR szEntry, ADDR _szWinFmt, \
            hWnd, ADDR _winTitleBuf, dwPid, rc.left, rc.top, eax, ecx
    invoke  lstrlenA, ADDR szEntry
    mov     ecx, eax
    mov     eax, _winListOff
    add     eax, ecx
    add     eax, 2
    cmp     eax, 65000
    jge     @wfc_stop
    cmp     _winListOff, 1
    je      @wfc_no_comma
    mov     edi, OFFSET _winListBuf
    add     edi, _winListOff
    mov     byte ptr [edi], ','
    inc     _winListOff
@wfc_no_comma:
    mov     edi, OFFSET _winListBuf
    add     edi, _winListOff
    invoke  RtlMoveMemory, edi, ADDR szEntry, ecx
    add     _winListOff, ecx
@wfc_next:
    mov     eax, 1
    ret
@wfc_stop:
    xor     eax, eax
    ret
_WinFindCallback ENDP

;; =============================================================================
;; _LookupVK — Map key name to VK code
;; Returns: VK code in eax, 0 if unknown
;; =============================================================================

_LookupVK PROC lpName:DWORD
    invoke  lstrcmpiA, lpName, ADDR _szKeyEnter
    test    eax, eax
    jz      @vk_enter
    invoke  lstrcmpiA, lpName, ADDR _szKeyEsc
    test    eax, eax
    jz      @vk_esc
    invoke  lstrcmpiA, lpName, ADDR _szKeyTab
    test    eax, eax
    jz      @vk_tab
    invoke  lstrcmpiA, lpName, ADDR _szKeyBack
    test    eax, eax
    jz      @vk_back
    invoke  lstrcmpiA, lpName, ADDR _szKeyDel
    test    eax, eax
    jz      @vk_del
    invoke  lstrcmpiA, lpName, ADDR _szKeyUp
    test    eax, eax
    jz      @vk_up
    invoke  lstrcmpiA, lpName, ADDR _szKeyDown
    test    eax, eax
    jz      @vk_down
    invoke  lstrcmpiA, lpName, ADDR _szKeyLeft
    test    eax, eax
    jz      @vk_left
    invoke  lstrcmpiA, lpName, ADDR _szKeyRight
    test    eax, eax
    jz      @vk_right
    invoke  lstrcmpiA, lpName, ADDR _szKeyHome
    test    eax, eax
    jz      @vk_home
    invoke  lstrcmpiA, lpName, ADDR _szKeyEnd
    test    eax, eax
    jz      @vk_end
    invoke  lstrcmpiA, lpName, ADDR _szKeyPgUp
    test    eax, eax
    jz      @vk_pgup
    invoke  lstrcmpiA, lpName, ADDR _szKeyPgDn
    test    eax, eax
    jz      @vk_pgdn
    invoke  lstrcmpiA, lpName, ADDR _szKeyF1
    test    eax, eax
    jz      @vk_f1
    invoke  lstrcmpiA, lpName, ADDR _szKeyF2
    test    eax, eax
    jz      @vk_f2
    invoke  lstrcmpiA, lpName, ADDR _szKeyF3
    test    eax, eax
    jz      @vk_f3
    invoke  lstrcmpiA, lpName, ADDR _szKeyF4
    test    eax, eax
    jz      @vk_f4
    invoke  lstrcmpiA, lpName, ADDR _szKeyF5
    test    eax, eax
    jz      @vk_f5
    invoke  lstrcmpiA, lpName, ADDR _szKeySpace
    test    eax, eax
    jz      @vk_space
    ;; Unknown key
    xor     eax, eax
    ret
@vk_enter:  mov eax, 0Dh
    ret
@vk_esc:    mov eax, 1Bh
    ret
@vk_tab:    mov eax, 09h
    ret
@vk_back:   mov eax, 08h
    ret
@vk_del:    mov eax, 2Eh
    ret
@vk_up:     mov eax, 26h
    ret
@vk_down:   mov eax, 28h
    ret
@vk_left:   mov eax, 25h
    ret
@vk_right:  mov eax, 27h
    ret
@vk_home:   mov eax, 24h
    ret
@vk_end:    mov eax, 23h
    ret
@vk_pgup:   mov eax, 21h
    ret
@vk_pgdn:   mov eax, 22h
    ret
@vk_f1:     mov eax, 70h
    ret
@vk_f2:     mov eax, 71h
    ret
@vk_f3:     mov eax, 72h
    ret
@vk_f4:     mov eax, 73h
    ret
@vk_f5:     mov eax, 74h
    ret
@vk_space:  mov eax, 20h
    ret
_LookupVK ENDP
