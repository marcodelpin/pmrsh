;; =============================================================================
;; main.asm — pmash entry point (thin dispatcher)
;; All logic in include modules: server.inc, client.inc, util.inc
;; =============================================================================

.686
.model flat, stdcall
option casemap:none

;; ---- Module includes (order matters: deps first) ----
include cli.inc
include net.inc
include tls.inc
include crypto.inc
include proto.inc
include util.inc
include exec.inc
include service.inc
include tray.inc
include transfer.inc
include selfupdate.inc
include screenshot.inc
include base64.inc
include json.inc
include auth.inc
include hash.inc
include compress.inc
include shell.inc
include sync.inc
include native.inc
include input.inc
include protobuf.inc
include relay.inc
include proxy.inc
include server.inc
include client.inc

;; ---- API ----
ExitProcess     PROTO :DWORD
CreateThread    PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
GetStdHandle    PROTO :DWORD
AttachConsole   PROTO :DWORD
lstrcmpiA       PROTO :DWORD, :DWORD

STD_OUTPUT_HANDLE equ -11
STD_ERROR_HANDLE  equ -12
ATTACH_PARENT_PROCESS equ 0FFFFFFFFh

.data
    szVersion   db "pmash 0.1.0", 13, 10, 0
    szUsage1    db "Usage: pmash -h <host> exec <cmd>", 13, 10
                db "       mrsh -h <host> push <local> <remote>", 13, 10
                db "       mrsh -h <host> pull <remote> <local>", 13, 10
                db "       mrsh -h <host> write <local> <remote>", 13, 10
                db "       mrsh -h <host> sync <remote> <local>", 13, 10
                db "       mrsh -h <host> screenshot [file.bmp]", 13, 10, 0
    szUsage2    db "       mrsh -h <host> ls [path] | cat <path>", 13, 10
                db "       mrsh -h <host> self-update <path>", 13, 10
                db "       mrsh -h <host> info | ping | shell", 13, 10
                db "       pmash -J <proxy> -h <target> exec <cmd>", 13, 10
                db "       pmash --install | --uninstall", 13, 10
                db "       pmash --tray | --console", 13, 10, 0
    szNoCmd     db "Error: command required", 13, 10, 0
    szVerCmd    db "version", 0

.code

;; Thread proc for tray server background
_TrayServerThread PROC lpParam:DWORD
    movzx   eax, word ptr lpParam
    invoke  ServerLoop, ax
    ret
_TrayServerThread ENDP

;; =============================================================================
;; Entry point
;; =============================================================================
start:
    invoke  AttachConsole, ATTACH_PARENT_PROCESS
    invoke  GetStdHandle, STD_OUTPUT_HANDLE
    mov     _hStdOut, eax
    invoke  GetStdHandle, STD_ERROR_HANDLE
    mov     _hStdErr, eax
    invoke  CliParse, ADDR cliArgs

    ;; Flags first
    cmp     cliArgs.bHelp, 1
    je      @show_help
    cmp     cliArgs.bVersion, 1
    je      @show_version
    cmp     cliArgs.bInstall, 1
    je      @install
    cmp     cliArgs.bUninstall, 1
    je      @uninstall
    cmp     cliArgs.bService, 1
    je      @service
    cmp     cliArgs.bConsole, 1
    je      @console
    cmp     cliArgs.bTray, 1
    je      @tray

    ;; Check "version" subcommand
    cmp     cliArgs.lpCommand, 0
    je      @default
    invoke  lstrcmpiA, cliArgs.lpCommand, ADDR szVerCmd
    test    eax, eax
    je      @show_version

    ;; -h → client mode
    cmp     cliArgs.lpHost, 0
    jne     @client

@default:
    ;; No flags, no host → try SCM, fallback to tray
    invoke  NetInit
    invoke  SvcDispatch
    test    eax, eax
    jz      @exit0
    invoke  CreateThread, 0, 0, ADDR _TrayServerThread, TRAY_PORT, 0, 0
    invoke  TrayRun, TRAY_PORT
@exit0:
    invoke  ExitProcess, 0

@client:
    cmp     cliArgs.lpCommand, 0
    jne     @do_client
    invoke  StdErr, ADDR szNoCmd
    invoke  ExitProcess, 1
@do_client:
    invoke  ClientMode

@show_version:
    invoke  StdOut, ADDR szVersion
    invoke  ExitProcess, 0

@show_help:
    invoke  StdOut, ADDR szVersion
    invoke  StdOut, ADDR szUsage1
    invoke  StdOut, ADDR szUsage2
    invoke  ExitProcess, 0

@install:
    invoke  SvcInstall
    invoke  ExitProcess, 0

@uninstall:
    invoke  SvcUninstall
    invoke  ExitProcess, 0

@tray:
    invoke  NetInit
    invoke  CreateThread, 0, 0, ADDR _TrayServerThread, TRAY_PORT, 0, 0
    invoke  TrayRun, TRAY_PORT
    invoke  ExitProcess, 0

@service:
    invoke  NetInit
    invoke  SvcDispatch
    invoke  ExitProcess, 0

@console:
    invoke  NetInit
    movzx   eax, cliArgs.wPort
    test    eax, eax
    jnz     @console_port
    mov     eax, DEFAULT_PORT
@console_port:
    invoke  ServerLoop, ax
    invoke  ExitProcess, 0

end start
