;; =============================================================================
;; selfupdate.inc — Remote self-update via schtask
;; Part of pmash — lightweight remote agent
;; =============================================================================

CreateFileA     PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
WriteFile       PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
CloseHandle     PROTO :DWORD
GetModuleFileNameA PROTO :DWORD, :DWORD, :DWORD
GetTempPathA    PROTO :DWORD, :DWORD
wsprintfA       PROTO C :DWORD, :DWORD, :VARARG
lstrlenA        PROTO :DWORD

IFNDEF _GLOBALALLOC_DEFINED
_GLOBALALLOC_DEFINED equ 1
GlobalAlloc     PROTO :DWORD, :DWORD
GlobalFree      PROTO :DWORD
ENDIF
IFNDEF CREATE_ALWAYS
CREATE_ALWAYS   equ 2
ENDIF
IFNDEF GENERIC_WRITE
GENERIC_WRITE   equ 40000000h
ENDIF
IFNDEF FILE_ATTRIBUTE_NORMAL
FILE_ATTRIBUTE_NORMAL equ 80h
ENDIF
IFNDEF INVALID_HANDLE_VALUE
INVALID_HANDLE_VALUE equ 0FFFFFFFFh
ENDIF

;; Use CreateProcess to run schtasks
CreateProcessA  PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, \
                      :DWORD, :DWORD, :DWORD, :DWORD, :DWORD

WinExec         PROTO :DWORD, :DWORD

.data
    szFmtPath   db "%s%s", 0
    szCmdFmt    db "cmd /c %s", 0
    szUpdateBat db "@echo off", 13, 10
                db "net stop mrsh", 13, 10
                db "timeout /t 5 /nobreak >nul", 13, 10
                db "taskkill /F /IM mrsh.exe >nul 2>&1", 13, 10
                db "timeout /t 3 /nobreak >nul", 13, 10
                db "copy /y ", 22, "%s", 22, " ", 22, "%s", 22, 13, 10
                db "net start mrsh", 13, 10
                db "schtasks /run /tn mrsh-tray", 13, 10
                db "schtasks /delete /tn mrsh-self-update /f", 13, 10, 0
    szSchtaskCmd db "schtasks /create /tn mrsh-self-update /tr ""%s"" /sc once /st 00:00 /ru SYSTEM /f", 0
    szSchtaskRun db "schtasks /run /tn mrsh-self-update", 0
    szBatName    db "mrsh-update.bat", 0
    szOkMsg      db "update scheduled, service will restart in ~10 seconds", 0

_RunCmd PROTO :DWORD

.code

;; =============================================================================
;; SelfUpdate — Schedule binary replacement + service restart
;; Args: lpNewBinaryPath (path to new binary on this machine)
;; Returns: 0 = success, -1 = error
;; =============================================================================
SelfUpdate PROC lpNewBinaryPath:DWORD
    LOCAL   szExePath[520]:BYTE
    LOCAL   szTempDir[260]:BYTE
    LOCAL   szBatPath[520]:BYTE
    LOCAL   szBatContent[2048]:BYTE
    LOCAL   szCmd[1024]:BYTE
    LOCAL   hFile:DWORD
    LOCAL   dwWritten:DWORD

    ;; Get current exe path
    invoke  GetModuleFileNameA, 0, ADDR szExePath, 512

    ;; Get temp dir for bat file
    invoke  GetTempPathA, 260, ADDR szTempDir

    ;; Build bat path
    invoke  wsprintfA, ADDR szBatPath, ADDR szFmtPath, ADDR szTempDir, ADDR szBatName

    ;; Build bat content: copy new binary over current, restart service
    invoke  wsprintfA, ADDR szBatContent, ADDR szUpdateBat, \
            lpNewBinaryPath, ADDR szExePath

    ;; Write bat file
    invoke  CreateFileA, ADDR szBatPath, GENERIC_WRITE, 0, \
            0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0
    cmp     eax, INVALID_HANDLE_VALUE
    je      @su_fail
    mov     hFile, eax

    invoke  lstrlenA, ADDR szBatContent
    mov     ecx, eax    ; save length before invoke clobbers eax
    invoke  WriteFile, hFile, ADDR szBatContent, ecx, ADDR dwWritten, 0
    invoke  CloseHandle, hFile

    ;; Create schtask to run bat as SYSTEM
    invoke  wsprintfA, ADDR szCmd, ADDR szSchtaskCmd, ADDR szBatPath

    ;; Execute schtask creation via cmd
    invoke  _RunCmd, ADDR szCmd

    ;; Run the schtask
    invoke  _RunCmd, ADDR szSchtaskRun

    xor     eax, eax
    ret

@su_fail:
    mov     eax, -1
    ret
SelfUpdate ENDP

;; ---- Helper: run a command via cmd.exe ----
_RunCmd PROC lpCmd:DWORD
    LOCAL   szFull[1200]:BYTE
    LOCAL   sui:BYTE        ; dummy STARTUPINFO (68 bytes)
    LOCAL   pi:BYTE         ; dummy PROCESS_INFORMATION (16 bytes)

    invoke  wsprintfA, ADDR szFull, ADDR szCmdFmt, lpCmd
    ;; Use system() equivalent — simplest approach
    ;; Actually, just call CreateProcess with cmd /c
    ;; For simplicity, use WinExec (deprecated but works, 2 args)
    ;; WinExec is in kernel32
    invoke  WinExec, ADDR szFull, 0     ; SW_HIDE = 0
    ret
_RunCmd ENDP

