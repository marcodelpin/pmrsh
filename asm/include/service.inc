;; =============================================================================
;; service.inc — Windows SCM service registration + dispatch
;; Part of pmash — lightweight remote agent
;; =============================================================================

;; ---- SCM Constants ----
SC_MANAGER_CREATE_SERVICE   equ 0002h
SERVICE_ALL_ACCESS          equ 000F01FFh
SERVICE_WIN32_OWN_PROCESS   equ 00000010h
SERVICE_AUTO_START          equ 00000002h
SERVICE_ERROR_NORMAL        equ 00000001h
SERVICE_CONTROL_STOP        equ 00000001h
SERVICE_RUNNING             equ 00000004h
SERVICE_STOPPED             equ 00000001h
SERVICE_START_PENDING       equ 00000002h
SERVICE_STOP_PENDING        equ 00000003h
SERVICE_ACCEPT_STOP         equ 00000001h
SERVICE_ACCEPT_SHUTDOWN     equ 00000004h
DELETE                      equ 00010000h

;; ---- Structures ----
SERVICE_TABLE_ENTRYA STRUCT
    lpServiceName   DWORD ?
    lpServiceProc   DWORD ?
SERVICE_TABLE_ENTRYA ENDS

SERVICE_STATUS STRUCT
    dwServiceType              DWORD ?
    dwCurrentState             DWORD ?
    dwControlsAccepted         DWORD ?
    dwWin32ExitCode            DWORD ?
    dwServiceSpecificExitCode  DWORD ?
    dwCheckPoint               DWORD ?
    dwWaitHint                 DWORD ?
SERVICE_STATUS ENDS

;; ---- API Prototypes ----
OpenSCManagerA              PROTO :DWORD, :DWORD, :DWORD
CreateServiceA              PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, \
                                  :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, \
                                  :DWORD, :DWORD, :DWORD
DeleteService               PROTO :DWORD
OpenServiceA                PROTO :DWORD, :DWORD, :DWORD
CloseServiceHandle          PROTO :DWORD
StartServiceCtrlDispatcherA PROTO :DWORD
RegisterServiceCtrlHandlerA PROTO :DWORD, :DWORD
SetServiceStatus            PROTO :DWORD, :DWORD
GetModuleFileNameA          PROTO :DWORD, :DWORD, :DWORD

WinExec         PROTO :DWORD, :DWORD

IFNDEF _RTLZEROMEMORY_DEFINED
_RTLZEROMEMORY_DEFINED equ 1
RtlZeroMemory   PROTO :DWORD, :DWORD
ENDIF
lstrlenA        PROTO :DWORD
lstrcpyA        PROTO :DWORD, :DWORD
lstrcatA        PROTO :DWORD, :DWORD
wsprintfA       PROTO C :DWORD, :DWORD, :VARARG
IFNDEF _GLOBALALLOC_DEFINED
_GLOBALALLOC_DEFINED equ 1
GlobalAlloc     PROTO :DWORD, :DWORD
GlobalFree      PROTO :DWORD
ENDIF

.data
    szSvcName       db "mrsh", 0
    szSvcDisplay    db "mrsh - Remote Shell", 0
    szSvcSuffix     db " --service", 0
    szFmtBin        db "%s --service", 0
    szFwCmd         db "netsh advfirewall firewall add rule name=mrsh dir=in action=allow program=%s enable=yes", 0

.data?
    _hSvcStatus     DWORD ?     ; service status handle
    _svcStatus      SERVICE_STATUS <>
    _svcStopFlag    DWORD ?     ; set to 1 by control handler

;; Forward declare (defined in main.asm)
ServerLoop PROTO :WORD

.code

;; =============================================================================
;; SvcInstall — Register mrsh as a Windows service
;; Returns: 0 = success, -1 = error
;; =============================================================================
SvcInstall PROC
    LOCAL   hSCM:DWORD
    LOCAL   hSvc:DWORD
    LOCAL   szPath[520]:BYTE
    LOCAL   szBinPath[600]:BYTE

    ;; Get our exe path
    invoke  GetModuleFileNameA, 0, ADDR szPath, 512
    ;; Build "C:\...\mrsh.exe --service"
    invoke  wsprintfA, ADDR szBinPath, ADDR szFmtBin, ADDR szPath

    ;; Open SCM
    invoke  OpenSCManagerA, 0, 0, SC_MANAGER_CREATE_SERVICE
    test    eax, eax
    jz      @si_fail
    mov     hSCM, eax

    ;; Try to delete existing service first (idempotent install)
    invoke  OpenServiceA, hSCM, ADDR szSvcName, DELETE
    test    eax, eax
    jz      @si_create
    invoke  DeleteService, eax
    invoke  CloseServiceHandle, eax

@si_create:
    invoke  CreateServiceA, \
            hSCM, \
            ADDR szSvcName, \
            ADDR szSvcDisplay, \
            SERVICE_ALL_ACCESS, \
            SERVICE_WIN32_OWN_PROCESS, \
            SERVICE_AUTO_START, \
            SERVICE_ERROR_NORMAL, \
            ADDR szBinPath, \
            0, 0, 0, 0, 0
    test    eax, eax
    jz      @si_close
    mov     hSvc, eax
    invoke  CloseServiceHandle, hSvc

@si_close:
    invoke  CloseServiceHandle, hSCM
    ;; Add firewall rule for mrsh
    invoke  wsprintfA, ADDR szBinPath, ADDR szFwCmd, ADDR szPath
    invoke  WinExec, ADDR szBinPath, 0
    xor     eax, eax
    ret

@si_fail:
    mov     eax, -1
    ret
SvcInstall ENDP

;; =============================================================================
;; SvcUninstall — Remove mrsh service
;; =============================================================================
SvcUninstall PROC
    LOCAL   hSCM:DWORD
    LOCAL   hSvc:DWORD

    invoke  OpenSCManagerA, 0, 0, SC_MANAGER_CREATE_SERVICE
    test    eax, eax
    jz      @su_fail
    mov     hSCM, eax

    invoke  OpenServiceA, hSCM, ADDR szSvcName, DELETE
    test    eax, eax
    jz      @su_close
    mov     hSvc, eax
    invoke  DeleteService, hSvc
    invoke  CloseServiceHandle, hSvc

@su_close:
    invoke  CloseServiceHandle, hSCM
    xor     eax, eax
    ret
@su_fail:
    mov     eax, -1
    ret
SvcUninstall ENDP

;; =============================================================================
;; SvcCtrlHandler — Service control callback
;; =============================================================================
SvcCtrlHandler PROC dwControl:DWORD
    cmp     dwControl, SERVICE_CONTROL_STOP
    jne     @sch_done

    ;; Signal stop
    mov     _svcStopFlag, 1
    mov     _svcStatus.dwCurrentState, SERVICE_STOP_PENDING
    mov     _svcStatus.dwWaitHint, 5000
    invoke  SetServiceStatus, _hSvcStatus, ADDR _svcStatus

@sch_done:
    ret
SvcCtrlHandler ENDP

;; =============================================================================
;; SvcMain — ServiceMain callback (called by SCM dispatcher)
;; Args: dwArgc, lpArgv (from SCM)
;; The actual server logic should be called from here.
;; =============================================================================
SvcMain PROC dwArgc:DWORD, lpArgv:DWORD
    ;; Register control handler
    invoke  RegisterServiceCtrlHandlerA, ADDR szSvcName, ADDR SvcCtrlHandler
    test    eax, eax
    jz      @sm_fail
    mov     _hSvcStatus, eax

    ;; Report running
    mov     _svcStatus.dwServiceType, SERVICE_WIN32_OWN_PROCESS
    mov     _svcStatus.dwCurrentState, SERVICE_RUNNING
    mov     _svcStatus.dwControlsAccepted, SERVICE_ACCEPT_STOP or SERVICE_ACCEPT_SHUTDOWN
    invoke  SetServiceStatus, _hSvcStatus, ADDR _svcStatus

    ;; Run server loop (defined in main.asm, blocks until stop)
    invoke  ServerLoop, 8822

    ;; Report stopped
    mov     _svcStatus.dwCurrentState, SERVICE_STOPPED
    invoke  SetServiceStatus, _hSvcStatus, ADDR _svcStatus

@sm_fail:
    ret
SvcMain ENDP

;; =============================================================================
;; SvcDispatch — Start SCM dispatcher (call from main when --service)
;; Returns: 0 = success (was service), -1 = not service context
;; =============================================================================
SvcDispatch PROC
    LOCAL   svcTable[2]:SERVICE_TABLE_ENTRYA

    ;; Build service table
    lea     eax, szSvcName
    mov     svcTable[0].lpServiceName, eax
    lea     eax, SvcMain
    mov     svcTable[0].lpServiceProc, eax
    mov     svcTable[1].lpServiceName, 0
    mov     svcTable[1].lpServiceProc, 0

    invoke  StartServiceCtrlDispatcherA, ADDR svcTable
    test    eax, eax
    jz      @sd_fail
    xor     eax, eax
    ret
@sd_fail:
    mov     eax, -1
    ret
SvcDispatch ENDP

