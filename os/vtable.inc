;; =============================================================================
;; vtable.inc — OS abstraction via runtime-patched function table
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; All code calls through os_vtable. At startup, detect_os + patch_vtable
;; fills the table with the correct OS-specific function pointers.
;; Zero branches in common code. One indirection per call (always in cache).
;; =============================================================================

bits 32

;; OS type constants
OS_UNKNOWN  equ 0
OS_WINDOWS  equ 1
OS_LINUX    equ 2

;; vtable entry count (for iteration/zeroing)
OS_VTABLE_ENTRIES equ 24

section .data

;; =============================================================================
;; os_vtable — Runtime-patched function pointer table
;; Calling convention: stdcall on Windows, cdecl-ish on Linux
;; All functions use a unified ABI:
;;   args on stack (push right-to-left), return in eax
;; =============================================================================

global os_vtable

os_vtable:
    ;; --- I/O ---
    .write:         dd 0    ; (fd, buf, len) → bytes written
    .read:          dd 0    ; (fd, buf, len) → bytes read
    .open:          dd 0    ; (path, flags) → fd (-1=error)
    .close:         dd 0    ; (fd) → 0
    .seek:          dd 0    ; (fd, offset, whence) → position
    .filesize:      dd 0    ; (fd) → size
    .rename:        dd 0    ; (old, new) → 0/err
    .unlink:        dd 0    ; (path) → 0/err
    .mkdir:         dd 0    ; (path) → 0/err

    ;; --- Network ---
    .socket:        dd 0    ; () → fd
    .connect:       dd 0    ; (fd, ip, port) → 0/err
    .bind:          dd 0    ; (fd, port) → 0/err
    .listen:        dd 0    ; (fd, backlog) → 0/err
    .accept:        dd 0    ; (fd) → new_fd
    .send:          dd 0    ; (fd, buf, len) → bytes sent
    .recv:          dd 0    ; (fd, buf, len) → bytes received
    .closesock:     dd 0    ; (fd) → 0

    ;; --- Process ---
    .exec:          dd 0    ; (cmd, outbuf, outbufsize) → output_len (-1=err)
    .getpid:        dd 0    ; () → pid
    .exit:          dd 0    ; (code) → noreturn

    ;; --- Memory ---
    .alloc:         dd 0    ; (size) → ptr (0=fail)
    .free:          dd 0    ; (ptr)

    ;; --- Misc ---
    .sleep_ms:      dd 0    ; (ms)
    .hostname:      dd 0    ; (buf, len) → actual_len

os_vtable_size equ $ - os_vtable

section .data
    _os_type    dd OS_UNKNOWN

section .text

;; =============================================================================
;; detect_os — Determine which OS we're running on
;; Returns: eax = OS_WINDOWS or OS_LINUX
;; Strategy: Try a Linux syscall (getpid). If it works, we're on Linux.
;; On Windows, int 0x80 or syscall with Linux numbers will fault or return
;; garbage. But safer: check if we were loaded as PE (Windows sets up
;; PEB/TEB) or as ELF.
;;
;; Simplest reliable method: check if FS segment base is non-zero.
;; Windows always sets FS to point to TEB. Linux leaves FS=0 for 32-bit.
;; =============================================================================

global detect_os
detect_os:
    ;; Method: Windows sets FS segment to TEB. Linux 32-bit has FS=0.
    ;; Read FS:[0x18] (TEB self-pointer on Windows). If valid, Windows.
    xor     eax, eax
    mov     ax, fs
    test    ax, ax
    jz      .is_linux

    ;; FS is non-zero — likely Windows. Verify by reading TEB self-pointer.
    mov     eax, [fs:0x18]      ; TEB.Self on Windows
    test    eax, eax
    jz      .is_linux           ; shouldn't happen but safety
    mov     eax, OS_WINDOWS
    mov     [_os_type], eax
    ret

.is_linux:
    mov     eax, OS_LINUX
    mov     [_os_type], eax
    ret

;; =============================================================================
;; patch_vtable — Fill os_vtable with OS-specific function pointers
;; Args: eax = OS type (OS_WINDOWS or OS_LINUX)
;; =============================================================================

global patch_vtable
patch_vtable:
    cmp     eax, OS_WINDOWS
    je      .patch_win

    ;; --- Linux implementations ---
    mov     dword [os_vtable.write],    _linux_write
    mov     dword [os_vtable.read],     _linux_read
    mov     dword [os_vtable.open],     _linux_open
    mov     dword [os_vtable.close],    _linux_close
    mov     dword [os_vtable.seek],     _linux_seek
    mov     dword [os_vtable.filesize], _linux_filesize
    mov     dword [os_vtable.rename],   _linux_rename
    mov     dword [os_vtable.unlink],   _linux_unlink
    mov     dword [os_vtable.mkdir],    _linux_mkdir
    mov     dword [os_vtable.socket],   _linux_socket
    mov     dword [os_vtable.connect],  _linux_connect
    mov     dword [os_vtable.bind],     _linux_bind
    mov     dword [os_vtable.listen],   _linux_listen
    mov     dword [os_vtable.accept],   _linux_accept
    mov     dword [os_vtable.send],     _linux_send
    mov     dword [os_vtable.recv],     _linux_recv
    mov     dword [os_vtable.closesock],_linux_close
    mov     dword [os_vtable.exec],     _linux_exec
    mov     dword [os_vtable.getpid],   _linux_getpid
    mov     dword [os_vtable.exit],     _linux_exit
    mov     dword [os_vtable.alloc],    _linux_alloc
    mov     dword [os_vtable.free],     _linux_free
    mov     dword [os_vtable.sleep_ms], _linux_sleep_ms
    mov     dword [os_vtable.hostname], _linux_hostname
    ret

.patch_win:
    mov     dword [os_vtable.write],    _win_write
    mov     dword [os_vtable.read],     _win_read
    mov     dword [os_vtable.open],     _win_open
    mov     dword [os_vtable.close],    _win_close
    mov     dword [os_vtable.seek],     _win_seek
    mov     dword [os_vtable.filesize], _win_filesize
    mov     dword [os_vtable.rename],   _win_rename
    mov     dword [os_vtable.unlink],   _win_unlink
    mov     dword [os_vtable.mkdir],    _win_mkdir
    mov     dword [os_vtable.socket],   _win_socket
    mov     dword [os_vtable.connect],  _win_connect
    mov     dword [os_vtable.bind],     _win_bind
    mov     dword [os_vtable.listen],   _win_listen
    mov     dword [os_vtable.accept],   _win_accept
    mov     dword [os_vtable.send],     _win_send
    mov     dword [os_vtable.recv],     _win_recv
    mov     dword [os_vtable.closesock],_win_closesock
    mov     dword [os_vtable.exec],     _win_exec
    mov     dword [os_vtable.getpid],   _win_getpid
    mov     dword [os_vtable.exit],     _win_exit
    mov     dword [os_vtable.alloc],    _win_alloc
    mov     dword [os_vtable.free],     _win_free
    mov     dword [os_vtable.sleep_ms], _win_sleep_ms
    mov     dword [os_vtable.hostname], _win_hostname
    ret

;; When building Linux-only, win symbols aren't defined — provide stubs
%ifndef HAS_WIN32
_win_write:
_win_read:
_win_open:
_win_close:
_win_seek:
_win_filesize:
_win_rename:
_win_unlink:
_win_mkdir:
_win_socket:
_win_connect:
_win_bind:
_win_listen:
_win_accept:
_win_send:
_win_recv:
_win_closesock:
_win_exec:
_win_getpid:
_win_alloc:
_win_free:
_win_sleep_ms:
_win_hostname:
    ud2                             ; trap: wrong OS path taken
_win_exit:
    ud2
%endif
