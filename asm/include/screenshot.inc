;; =============================================================================
;; screenshot.inc — Screen capture to BMP buffer
;; Part of pmash — lightweight remote agent
;; =============================================================================
;; Uses GDI: GetDC, BitBlt, CreateCompatibleDC/Bitmap
;; Returns raw BMP data (header + pixels) that client saves to file
;; =============================================================================

;; ---- GDI API Prototypes ----
GetDC           PROTO :DWORD
ReleaseDC       PROTO :DWORD, :DWORD
CreateCompatibleDC PROTO :DWORD
CreateCompatibleBitmap PROTO :DWORD, :DWORD, :DWORD
SelectObject    PROTO :DWORD, :DWORD
DeleteObject    PROTO :DWORD
DeleteDC        PROTO :DWORD
BitBlt          PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, \
                      :DWORD, :DWORD, :DWORD, :DWORD
GetSystemMetrics PROTO :DWORD
GetDIBits       PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD

IFNDEF _GLOBALALLOC_DEFINED
_GLOBALALLOC_DEFINED equ 1
GlobalAlloc     PROTO :DWORD, :DWORD
GlobalFree      PROTO :DWORD
ENDIF
IFNDEF _RTLZEROMEMORY_DEFINED
_RTLZEROMEMORY_DEFINED equ 1
RtlZeroMemory   PROTO :DWORD, :DWORD
ENDIF

SM_CXSCREEN     equ 0
SM_CYSCREEN     equ 1
SRCCOPY         equ 00CC0020h
BI_RGB          equ 0
DIB_RGB_COLORS  equ 0

;; ---- BITMAPINFOHEADER ----
BITMAPINFOHEADER STRUCT
    biSize          DWORD ?
    biWidth         DWORD ?
    biHeight        DWORD ?
    biPlanes        WORD  ?
    biBitCount      WORD  ?
    biCompression   DWORD ?
    biSizeImage     DWORD ?
    biXPelsPerMeter DWORD ?
    biYPelsPerMeter DWORD ?
    biClrUsed       DWORD ?
    biClrImportant  DWORD ?
BITMAPINFOHEADER ENDS

;; ---- BITMAPFILEHEADER ----
BITMAPFILEHEADER STRUCT
    bfType          WORD  ?
    bfSize          DWORD ?
    bfReserved1     WORD  ?
    bfReserved2     WORD  ?
    bfOffBits       DWORD ?
BITMAPFILEHEADER ENDS

.code

;; =============================================================================
;; ScreenCapture — Capture entire screen to BMP buffer
;; Args: ppBuf (out: GlobalAlloc'd BMP data), pBufLen (out: size)
;; Returns: 0 = success, -1 = error. Caller must GlobalFree *ppBuf.
;; =============================================================================
ScreenCapture PROC uses ebx esi edi \
    ppBuf:DWORD, pBufLen:DWORD

    LOCAL   scrW:DWORD           ; screen width
    LOCAL   scrH:DWORD           ; screen height
    LOCAL   hdcScreen:DWORD
    LOCAL   hdcMem:DWORD
    LOCAL   hBmp:DWORD
    LOCAL   hOld:DWORD
    LOCAL   bih:BITMAPINFOHEADER
    LOCAL   bfh:BITMAPFILEHEADER
    LOCAL   cbPixels:DWORD
    LOCAL   cbTotal:DWORD
    LOCAL   pBuf:DWORD

    ;; Get screen dimensions
    invoke  GetSystemMetrics, SM_CXSCREEN
    mov     scrW, eax
    invoke  GetSystemMetrics, SM_CYSCREEN
    mov     scrH, eax

    ;; Get screen DC
    invoke  GetDC, 0
    test    eax, eax
    jz      @sc_fail
    mov     hdcScreen, eax

    ;; Create compatible DC + bitmap
    invoke  CreateCompatibleDC, hdcScreen
    test    eax, eax
    jz      @sc_rel_screen
    mov     hdcMem, eax

    invoke  CreateCompatibleBitmap, hdcScreen, scrW, scrH
    test    eax, eax
    jz      @sc_del_dc
    mov     hBmp, eax

    invoke  SelectObject, hdcMem, hBmp
    mov     hOld, eax

    ;; BitBlt screen → memory DC
    invoke  BitBlt, hdcMem, 0, 0, scrW, scrH, hdcScreen, 0, 0, SRCCOPY

    ;; Setup BITMAPINFOHEADER for 24-bit
    invoke  RtlZeroMemory, ADDR bih, SIZEOF BITMAPINFOHEADER
    mov     bih.biSize, SIZEOF BITMAPINFOHEADER
    mov     eax, scrW
    mov     bih.biWidth, eax
    mov     eax, scrH
    mov     bih.biHeight, eax
    mov     bih.biPlanes, 1
    mov     bih.biBitCount, 24
    mov     bih.biCompression, BI_RGB

    ;; Calculate pixel data size (rows aligned to 4 bytes)
    ;; rowBytes = ((width * 3 + 3) & ~3)
    mov     eax, scrW
    imul    eax, 3
    add     eax, 3
    and     eax, 0FFFFFFFCh
    imul    eax, scrH
    mov     cbPixels, eax

    mov     bih.biSizeImage, eax

    ;; Total = BITMAPFILEHEADER + BITMAPINFOHEADER + pixels
    mov     eax, cbPixels
    add     eax, SIZEOF BITMAPFILEHEADER
    add     eax, SIZEOF BITMAPINFOHEADER
    mov     cbTotal, eax

    ;; Allocate output buffer
    invoke  GlobalAlloc, 0, cbTotal
    test    eax, eax
    jz      @sc_cleanup
    mov     pBuf, eax

    ;; Fill BITMAPFILEHEADER
    invoke  RtlZeroMemory, ADDR bfh, SIZEOF BITMAPFILEHEADER
    mov     bfh.bfType, 4D42h          ; "BM"
    mov     eax, cbTotal
    mov     bfh.bfSize, eax
    mov     eax, SIZEOF BITMAPFILEHEADER
    add     eax, SIZEOF BITMAPINFOHEADER
    mov     bfh.bfOffBits, eax

    ;; Copy file header to buffer
    mov     edi, pBuf
    invoke  RtlMoveMemory, edi, ADDR bfh, SIZEOF BITMAPFILEHEADER

    ;; Copy info header
    mov     edi, pBuf
    add     edi, SIZEOF BITMAPFILEHEADER
    invoke  RtlMoveMemory, edi, ADDR bih, SIZEOF BITMAPINFOHEADER

    ;; Get pixel data via GetDIBits
    mov     edi, pBuf
    add     edi, SIZEOF BITMAPFILEHEADER
    add     edi, SIZEOF BITMAPINFOHEADER
    invoke  GetDIBits, hdcMem, hBmp, 0, scrH, edi, ADDR bih, DIB_RGB_COLORS

    ;; Store result
    mov     edx, ppBuf
    mov     eax, pBuf
    mov     [edx], eax
    mov     edx, pBufLen
    mov     eax, cbTotal
    mov     [edx], eax

    ;; Cleanup
    invoke  SelectObject, hdcMem, hOld
    invoke  DeleteObject, hBmp
    invoke  DeleteDC, hdcMem
    invoke  ReleaseDC, 0, hdcScreen

    xor     eax, eax
    ret

@sc_cleanup:
    invoke  SelectObject, hdcMem, hOld
    invoke  DeleteObject, hBmp
@sc_del_dc:
    invoke  DeleteDC, hdcMem
@sc_rel_screen:
    invoke  ReleaseDC, 0, hdcScreen
@sc_fail:
    mov     eax, -1
    ret
ScreenCapture ENDP
