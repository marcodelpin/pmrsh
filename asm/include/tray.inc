;; =============================================================================
;; tray.inc — System tray icon (Shell_NotifyIconA)
;; Part of pmash — lightweight remote agent
;; =============================================================================

;; ---- Shell constants ----
NIM_ADD         equ 00000000h
NIM_DELETE      equ 00000002h
NIF_ICON        equ 00000002h
NIF_MESSAGE     equ 00000001h
NIF_TIP         equ 00000004h

WM_USER         equ 0400h
WM_TRAYICON     equ WM_USER + 1
WM_RBUTTONUP    equ 0205h
WM_LBUTTONUP    equ 0202h
WM_DESTROY      equ 0002h
WM_COMMAND      equ 0111h
WM_TIMER        equ 0113h
IDI_APPLICATION equ 32512

MF_STRING       equ 0000h
MF_SEPARATOR    equ 0800h
TPM_BOTTOMALIGN equ 0020h
TPM_RIGHTALIGN  equ 0008h

IDM_EXIT        equ 1001
IDM_ABOUT       equ 1002

;; ---- Structures ----
NOTIFYICONDATAA STRUCT
    cbSize          DWORD ?
    hWnd            DWORD ?
    uID             DWORD ?
    uFlags          DWORD ?
    uCallbackMessage DWORD ?
    hIcon           DWORD ?
    szTip           BYTE 128 dup(?)
NOTIFYICONDATAA ENDS

WNDCLASSA STRUCT
    style           DWORD ?
    lpfnWndProc     DWORD ?
    cbClsExtra      DWORD ?
    cbWndExtra      DWORD ?
    hInstance       DWORD ?
    hIcon           DWORD ?
    hCursor         DWORD ?
    hbrBackground   DWORD ?
    lpszMenuName    DWORD ?
    lpszClassName   DWORD ?
WNDCLASSA ENDS

POINT STRUCT
    x   DWORD ?
    y   DWORD ?
POINT ENDS

MSG STRUCT
    hwnd    DWORD ?
    message DWORD ?
    wParam  DWORD ?
    lParam  DWORD ?
    time    DWORD ?
    pt      POINT <>
MSG ENDS

;; ---- API ----
Shell_NotifyIconA   PROTO :DWORD, :DWORD
RegisterClassA      PROTO :DWORD
CreateWindowExA     PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, \
                          :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
DestroyWindow       PROTO :DWORD
PostQuitMessage     PROTO :DWORD
DefWindowProcA      PROTO :DWORD, :DWORD, :DWORD, :DWORD
GetMessageA         PROTO :DWORD, :DWORD, :DWORD, :DWORD
TranslateMessage    PROTO :DWORD
DispatchMessageA    PROTO :DWORD
LoadIconA           PROTO :DWORD, :DWORD
GetModuleHandleA    PROTO :DWORD
CreatePopupMenu     PROTO
InsertMenuA         PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
TrackPopupMenu      PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
DestroyMenu         PROTO :DWORD
GetCursorPos        PROTO :DWORD
SetForegroundWindow PROTO :DWORD
PostMessageA        PROTO :DWORD, :DWORD, :DWORD, :DWORD
IFNDEF _RTLZEROMEMORY_DEFINED
_RTLZEROMEMORY_DEFINED equ 1
RtlZeroMemory   PROTO :DWORD, :DWORD
ENDIF
wsprintfA       PROTO C :DWORD, :DWORD, :VARARG

HWND_MESSAGE    equ -3

.data
    szTrayClass db "mrsh_tray", 0
    szTrayTip   db "mrsh (asm)", 0
    szMenuExit  db "Exit", 0
    szMenuAbout db "pmash 0.1.0", 0
    szFmtTip    db "mrsh v0.1.0 (port %d)", 0

.data?
    _trayNid    NOTIFYICONDATAA <>
    _trayHwnd   DWORD ?
    _trayHInst  DWORD ?

.code

;; =============================================================================
;; TrayWndProc — Window procedure for tray message window
;; =============================================================================
TrayWndProc PROC hWnd:DWORD, uMsg:DWORD, wParam:DWORD, lParam:DWORD
    LOCAL   hMenu:DWORD
    LOCAL   pt:POINT

    .if uMsg == WM_TRAYICON
        .if lParam == WM_RBUTTONUP
            ;; Show context menu
            invoke  GetCursorPos, ADDR pt
            invoke  CreatePopupMenu
            mov     hMenu, eax
            invoke  InsertMenuA, hMenu, 0, MF_STRING, IDM_ABOUT, ADDR szMenuAbout
            invoke  InsertMenuA, hMenu, 1, MF_SEPARATOR, 0, 0
            invoke  InsertMenuA, hMenu, 2, MF_STRING, IDM_EXIT, ADDR szMenuExit
            invoke  SetForegroundWindow, hWnd
            invoke  TrackPopupMenu, hMenu, \
                    TPM_BOTTOMALIGN or TPM_RIGHTALIGN, \
                    pt.x, pt.y, 0, hWnd, 0
            invoke  DestroyMenu, hMenu
        .endif
    .elseif uMsg == WM_COMMAND
        .if wParam == IDM_EXIT
            ;; Remove tray icon + quit
            invoke  Shell_NotifyIconA, NIM_DELETE, ADDR _trayNid
            invoke  DestroyWindow, hWnd
        .endif
    .elseif uMsg == WM_DESTROY
        invoke  PostQuitMessage, 0
    .else
        invoke  DefWindowProcA, hWnd, uMsg, wParam, lParam
        ret
    .endif
    xor     eax, eax
    ret
TrayWndProc ENDP

;; =============================================================================
;; TrayRun — Create tray icon and run message loop
;; Args: wPort (for tooltip display)
;; Does not return until Exit is selected.
;; =============================================================================
TrayRun PROC wPort:WORD
    LOCAL   wc:WNDCLASSA
    LOCAL   msg:MSG
    LOCAL   szTip[128]:BYTE

    invoke  GetModuleHandleA, 0
    mov     _trayHInst, eax

    ;; Register window class
    invoke  RtlZeroMemory, ADDR wc, SIZEOF WNDCLASSA
    mov     wc.lpfnWndProc, OFFSET TrayWndProc
    mov     eax, _trayHInst
    mov     wc.hInstance, eax
    lea     eax, szTrayClass
    mov     wc.lpszClassName, eax
    invoke  RegisterClassA, ADDR wc

    ;; Create message-only window
    invoke  CreateWindowExA, 0, ADDR szTrayClass, 0, 0, \
            0, 0, 0, 0, HWND_MESSAGE, 0, _trayHInst, 0
    mov     _trayHwnd, eax

    ;; Build tooltip
    movzx   eax, wPort
    invoke  wsprintfA, ADDR szTip, ADDR szFmtTip, eax

    ;; Setup NOTIFYICONDATA
    invoke  RtlZeroMemory, ADDR _trayNid, SIZEOF NOTIFYICONDATAA
    mov     _trayNid.cbSize, SIZEOF NOTIFYICONDATAA
    mov     eax, _trayHwnd
    mov     _trayNid.hWnd, eax
    mov     _trayNid.uID, 1
    mov     _trayNid.uFlags, NIF_ICON or NIF_MESSAGE or NIF_TIP
    mov     _trayNid.uCallbackMessage, WM_TRAYICON

    ;; Load icon — try embedded resource (ID 1), fallback to system icon
    invoke  LoadIconA, _trayHInst, 1
    test    eax, eax
    jnz     @icon_ok
    invoke  LoadIconA, 0, IDI_APPLICATION
@icon_ok:
    mov     _trayNid.hIcon, eax

    ;; Copy tooltip
    lea     edi, _trayNid.szTip
    lea     esi, szTip
    mov     ecx, 127
@copy_tip:
    mov     al, byte ptr [esi]
    mov     byte ptr [edi], al
    test    al, al
    jz      @tip_done
    inc     esi
    inc     edi
    dec     ecx
    jnz     @copy_tip
@tip_done:

    ;; Add tray icon
    invoke  Shell_NotifyIconA, NIM_ADD, ADDR _trayNid

    ;; Message loop
@msg_loop:
    invoke  GetMessageA, ADDR msg, 0, 0, 0
    test    eax, eax
    jz      @msg_done
    invoke  TranslateMessage, ADDR msg
    invoke  DispatchMessageA, ADDR msg
    jmp     @msg_loop

@msg_done:
    ret
TrayRun ENDP

