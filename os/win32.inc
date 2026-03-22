;; =============================================================================
;; win32.inc — Windows x86 (32-bit) API implementations
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; Uses kernel32/ws2_32 via stdcall. Assumes DLLs already loaded (PE import).
;; All functions match the vtable signature (args on stack).
;; =============================================================================
;; NOTE: These are stubs referencing the existing MASM implementations.
;; The actual code lives in asm/include/*.inc (MASM syntax).
;; This file will be populated when we port from MASM to NASM.
;; For now, it declares the function labels that vtable.inc references.
;; =============================================================================

;; Windows API prototypes (will be resolved via PE import table)
extern _GetStdHandle@4
extern _WriteFile@20
extern _ReadFile@20
extern _CreateFileA@28
extern _CloseHandle@4
extern _SetFilePointer@16
extern _GetFileSize@8
extern _MoveFileExA@12
extern _DeleteFileA@4
extern _CreateDirectoryA@8
extern _GetComputerNameA@8
extern _ExitProcess@4
extern _Sleep@4
extern _GlobalAlloc@8
extern _GlobalFree@4
extern _GetCurrentProcessId@0

;; Winsock
extern _WSAStartup@8
extern _socket@12
extern _connect@12
extern _bind@12
extern _listen@8
extern _accept@12
extern _send@16
extern _recv@16
extern _closesocket@4
extern _htons@4

section .data
    _win_wsadata resb 400           ; WSADATA structure

section .bss
    _win_hStdOut resd 1
    _win_hStdErr resd 1
    _win_dwWritten resd 1
    _win_sa resb 16                 ; sockaddr_in

section .text

;; --- Winsock init (called once at startup) ---
_win_net_init:
    push    _win_wsadata
    push    0x0202                  ; version 2.2
    call    _WSAStartup@8
    ;; Get stdout handle
    push    -11                     ; STD_OUTPUT_HANDLE
    call    _GetStdHandle@4
    mov     [_win_hStdOut], eax
    push    -12
    call    _GetStdHandle@4
    mov     [_win_hStdErr], eax
    ret

;; --- I/O ---

_win_write:     ; (fd, buf, len) → bytes written
    push    0                       ; lpOverlapped
    push    _win_dwWritten          ; lpNumberOfBytesWritten
    push    dword [esp+20]          ; nNumberOfBytesToWrite (len)
    push    dword [esp+20]          ; lpBuffer (buf)
    push    dword [esp+20]          ; hFile (fd)
    call    _WriteFile@20
    mov     eax, [_win_dwWritten]
    ret

_win_read:      ; (fd, buf, len) → bytes read
    push    0
    push    _win_dwWritten
    push    dword [esp+20]
    push    dword [esp+20]
    push    dword [esp+20]
    call    _ReadFile@20
    mov     eax, [_win_dwWritten]
    ret

_win_open:      ; (path, flags) → fd
    ;; Map our flags to Windows: 0=RDONLY→GENERIC_READ, 1=WRONLY→GENERIC_WRITE
    mov     eax, [esp+8]           ; flags
    test    eax, eax
    jnz     .open_write
    ;; Read: OPEN_EXISTING
    push    0                       ; hTemplateFile
    push    0x80                    ; FILE_ATTRIBUTE_NORMAL
    push    3                       ; OPEN_EXISTING
    push    0                       ; lpSecurityAttributes
    push    1                       ; FILE_SHARE_READ
    push    0x80000000              ; GENERIC_READ
    push    dword [esp+28]          ; lpFileName
    call    _CreateFileA@28
    ret
.open_write:
    ;; Write: CREATE_ALWAYS
    push    0
    push    0x80
    push    2                       ; CREATE_ALWAYS
    push    0
    push    0
    push    0x40000000              ; GENERIC_WRITE
    push    dword [esp+28]
    call    _CreateFileA@28
    ret

_win_close:     ; (fd)
    push    dword [esp+4]
    call    _CloseHandle@4
    ret

_win_seek:      ; (fd, offset, whence)
    push    dword [esp+12]          ; dwMoveMethod
    push    0                       ; lpDistanceToMoveHigh
    push    dword [esp+12]          ; lDistanceToMove
    push    dword [esp+16]          ; hFile
    call    _SetFilePointer@16
    ret

_win_filesize:  ; (fd) → size
    push    0
    push    dword [esp+8]
    call    _GetFileSize@8
    ret

_win_rename:    ; (old, new)
    push    1                       ; MOVEFILE_REPLACE_EXISTING
    push    dword [esp+12]
    push    dword [esp+12]
    call    _MoveFileExA@12
    ret

_win_unlink:    ; (path)
    push    dword [esp+4]
    call    _DeleteFileA@4
    ret

_win_mkdir:     ; (path)
    push    0
    push    dword [esp+8]
    call    _CreateDirectoryA@8
    ret

;; --- Network ---

_win_socket:    ; () → fd
    push    0                       ; protocol
    push    1                       ; SOCK_STREAM
    push    2                       ; AF_INET
    call    _socket@12
    ret

_win_connect:   ; (fd, ip, port)
    ;; Build sockaddr_in
    mov     word [_win_sa], 2       ; AF_INET
    mov     eax, [esp+12]           ; port
    push    eax
    call    _htons@4
    mov     [_win_sa+2], ax
    mov     eax, [esp+8]            ; ip (already network order)
    mov     [_win_sa+4], eax
    mov     dword [_win_sa+8], 0
    mov     dword [_win_sa+12], 0
    push    16
    push    _win_sa
    push    dword [esp+12]          ; fd
    call    _connect@12
    ret

_win_bind:      ; (fd, port)
    mov     word [_win_sa], 2
    mov     eax, [esp+8]
    push    eax
    call    _htons@4
    mov     [_win_sa+2], ax
    mov     dword [_win_sa+4], 0    ; INADDR_ANY
    mov     dword [_win_sa+8], 0
    mov     dword [_win_sa+12], 0
    push    16
    push    _win_sa
    push    dword [esp+12]
    call    _bind@12
    ret

_win_listen:    ; (fd, backlog)
    push    dword [esp+8]
    push    dword [esp+8]
    call    _listen@8
    ret

_win_accept:    ; (fd) → new_fd
    push    0
    push    0
    push    dword [esp+12]
    call    _accept@12
    ret

_win_send:      ; (fd, buf, len)
    push    0                       ; flags
    push    dword [esp+16]
    push    dword [esp+16]
    push    dword [esp+16]
    call    _send@16
    ret

_win_recv:      ; (fd, buf, len)
    push    0
    push    dword [esp+16]
    push    dword [esp+16]
    push    dword [esp+16]
    call    _recv@16
    ret

_win_closesock: ; (fd)
    push    dword [esp+4]
    call    _closesocket@4
    ret

;; --- Process ---

_win_exec:      ; (cmd, outbuf, outbufsize) → output_len
    ;; TODO: CreateProcess + pipe capture (port from MASM exec.inc)
    mov     eax, -1
    ret

_win_getpid:
    call    _GetCurrentProcessId@0
    ret

_win_exit:      ; (code)
    push    dword [esp+4]
    call    _ExitProcess@4

;; --- Memory ---

_win_alloc:     ; (size) → ptr
    push    dword [esp+4]
    push    0                       ; GMEM_FIXED
    call    _GlobalAlloc@8
    ret

_win_free:      ; (ptr)
    push    dword [esp+4]
    call    _GlobalFree@4
    ret

_win_sleep_ms:  ; (ms)
    push    dword [esp+4]
    call    _Sleep@4
    ret

_win_hostname:  ; (buf, len) → actual_len
    push    esp                     ; hack: use len as in/out
    mov     eax, [esp+12]
    mov     [esp], eax              ; store len
    push    dword [esp+8]           ; buf
    call    _GetComputerNameA@8
    mov     eax, [_win_dwWritten]   ; approximate — GetComputerName doesn't return len easily
    ret
