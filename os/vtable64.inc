;; =============================================================================
;; vtable64.inc — OS abstraction via runtime-patched function table (x86_64)
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; All code calls through os_vtable. At startup, detect_os + patch_vtable
;; fills the table with the correct OS-specific function pointers.
;; x86_64 ABI: args in rdi/rsi/rdx/rcx/r8/r9, return in rax
;; =============================================================================

bits 64
default rel

;; OS type constants
OS_UNKNOWN  equ 0
OS_WINDOWS  equ 1
OS_LINUX    equ 2

;; vtable entry count
OS_VTABLE_ENTRIES equ 24

section .data

;; =============================================================================
;; os_vtable — Runtime-patched function pointer table (8-byte pointers)
;; Calling convention: System V AMD64 on Linux, Win64 on Windows
;; All functions: args in registers, return in rax
;; =============================================================================

global os_vtable

os_vtable:
    ;; --- I/O ---
    .write:         dq 0    ; (fd, buf, len) → bytes written
    .read:          dq 0    ; (fd, buf, len) → bytes read
    .open:          dq 0    ; (path, flags) → fd (-1=error)
    .close:         dq 0    ; (fd) → 0
    .seek:          dq 0    ; (fd, offset, whence) → position
    .filesize:      dq 0    ; (fd) → size
    .rename:        dq 0    ; (old, new) → 0/err
    .unlink:        dq 0    ; (path) → 0/err
    .mkdir:         dq 0    ; (path) → 0/err

    ;; --- Network ---
    .socket:        dq 0    ; () → fd
    .connect:       dq 0    ; (fd, ip, port) → 0/err
    .bind:          dq 0    ; (fd, port) → 0/err
    .listen:        dq 0    ; (fd, backlog) → 0/err
    .accept:        dq 0    ; (fd) → new_fd
    .send:          dq 0    ; (fd, buf, len) → bytes sent
    .recv:          dq 0    ; (fd, buf, len) → bytes received
    .closesock:     dq 0    ; (fd) → 0

    ;; --- Process ---
    .exec:          dq 0    ; (cmd, outbuf, outbufsize) → output_len (-1=err)
    .getpid:        dq 0    ; () → pid
    .exit:          dq 0    ; (code) → noreturn

    ;; --- Memory ---
    .alloc:         dq 0    ; (size) → ptr (0=fail)
    .free:          dq 0    ; (ptr)

    ;; --- Misc ---
    .sleep_ms:      dq 0    ; (ms)
    .hostname:      dq 0    ; (buf, len) → actual_len

os_vtable_size equ $ - os_vtable

section .data
    _os_type    dd OS_UNKNOWN

section .text

;; =============================================================================
;; detect_os — Determine which OS we're running on
;; Returns: eax = OS_WINDOWS or OS_LINUX
;; x86_64: Check GS segment (Windows uses GS for TEB in 64-bit)
;; =============================================================================

global detect_os
detect_os:
    ;; On x86_64: Windows uses GS for TEB, Linux uses FS for TLS
    ;; Check GS:[0x30] (TEB.Self on 64-bit Windows)
    ;; On Linux, reading GS:xxx with GS=0 would fault — but we can check
    ;; by trying a Linux syscall (getpid=39) which is harmless
    mov     eax, 39             ; SYS_GETPID
    syscall
    test    eax, eax
    jle     .is_windows         ; Linux getpid always returns > 0
    mov     dword [_os_type], OS_LINUX
    mov     eax, OS_LINUX
    ret

.is_windows:
    mov     dword [_os_type], OS_WINDOWS
    mov     eax, OS_WINDOWS
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
    lea     rcx, [_linux_write]
    mov     [os_vtable.write], rcx
    lea     rcx, [_linux_read]
    mov     [os_vtable.read], rcx
    lea     rcx, [_linux_open]
    mov     [os_vtable.open], rcx
    lea     rcx, [_linux_close]
    mov     [os_vtable.close], rcx
    lea     rcx, [_linux_seek]
    mov     [os_vtable.seek], rcx
    lea     rcx, [_linux_filesize]
    mov     [os_vtable.filesize], rcx
    lea     rcx, [_linux_rename]
    mov     [os_vtable.rename], rcx
    lea     rcx, [_linux_unlink]
    mov     [os_vtable.unlink], rcx
    lea     rcx, [_linux_mkdir]
    mov     [os_vtable.mkdir], rcx
    lea     rcx, [_linux_socket]
    mov     [os_vtable.socket], rcx
    lea     rcx, [_linux_connect]
    mov     [os_vtable.connect], rcx
    lea     rcx, [_linux_bind]
    mov     [os_vtable.bind], rcx
    lea     rcx, [_linux_listen]
    mov     [os_vtable.listen], rcx
    lea     rcx, [_linux_accept]
    mov     [os_vtable.accept], rcx
    lea     rcx, [_linux_send]
    mov     [os_vtable.send], rcx
    lea     rcx, [_linux_recv]
    mov     [os_vtable.recv], rcx
    lea     rcx, [_linux_close]
    mov     [os_vtable.closesock], rcx
    lea     rcx, [_linux_exec]
    mov     [os_vtable.exec], rcx
    lea     rcx, [_linux_getpid]
    mov     [os_vtable.getpid], rcx
    lea     rcx, [_linux_exit]
    mov     [os_vtable.exit], rcx
    lea     rcx, [_linux_alloc]
    mov     [os_vtable.alloc], rcx
    lea     rcx, [_linux_free]
    mov     [os_vtable.free], rcx
    lea     rcx, [_linux_sleep_ms]
    mov     [os_vtable.sleep_ms], rcx
    lea     rcx, [_linux_hostname]
    mov     [os_vtable.hostname], rcx
    ret

.patch_win:
    lea     rcx, [_win_write]
    mov     [os_vtable.write], rcx
    lea     rcx, [_win_read]
    mov     [os_vtable.read], rcx
    lea     rcx, [_win_open]
    mov     [os_vtable.open], rcx
    lea     rcx, [_win_close]
    mov     [os_vtable.close], rcx
    lea     rcx, [_win_seek]
    mov     [os_vtable.seek], rcx
    lea     rcx, [_win_filesize]
    mov     [os_vtable.filesize], rcx
    lea     rcx, [_win_rename]
    mov     [os_vtable.rename], rcx
    lea     rcx, [_win_unlink]
    mov     [os_vtable.unlink], rcx
    lea     rcx, [_win_mkdir]
    mov     [os_vtable.mkdir], rcx
    lea     rcx, [_win_socket]
    mov     [os_vtable.socket], rcx
    lea     rcx, [_win_connect]
    mov     [os_vtable.connect], rcx
    lea     rcx, [_win_bind]
    mov     [os_vtable.bind], rcx
    lea     rcx, [_win_listen]
    mov     [os_vtable.listen], rcx
    lea     rcx, [_win_accept]
    mov     [os_vtable.accept], rcx
    lea     rcx, [_win_send]
    mov     [os_vtable.send], rcx
    lea     rcx, [_win_recv]
    mov     [os_vtable.recv], rcx
    lea     rcx, [_win_closesock]
    mov     [os_vtable.closesock], rcx
    lea     rcx, [_win_exec]
    mov     [os_vtable.exec], rcx
    lea     rcx, [_win_getpid]
    mov     [os_vtable.getpid], rcx
    lea     rcx, [_win_exit]
    mov     [os_vtable.exit], rcx
    lea     rcx, [_win_alloc]
    mov     [os_vtable.alloc], rcx
    lea     rcx, [_win_free]
    mov     [os_vtable.free], rcx
    lea     rcx, [_win_sleep_ms]
    mov     [os_vtable.sleep_ms], rcx
    lea     rcx, [_win_hostname]
    mov     [os_vtable.hostname], rcx
    ret

;; When building Linux-only, win symbols aren't defined — provide stubs
%ifndef HAS_WIN64
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
