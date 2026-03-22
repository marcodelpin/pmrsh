;; fulltest.asm — Compilation gate: all modules link together
.686
.model flat, stdcall
option casemap:none
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
include auth.inc
include server.inc
include client.inc

CertOpenStore PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
CertCloseStore PROTO :DWORD, :DWORD
CertFindCertificateInStore PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
CertCreateSelfSignCertificate PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
CertAddCertificateContextToStore PROTO :DWORD, :DWORD, :DWORD, :DWORD
CertFreeCertificateContext PROTO :DWORD
CertStrToNameA PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD

RtlMoveMemory PROTO :DWORD, :DWORD, :DWORD
RtlZeroMemory PROTO :DWORD, :DWORD
ExitProcess PROTO :DWORD
GetStdHandle PROTO :DWORD
CreateThread PROTO :DWORD, :DWORD, :DWORD, :DWORD, :DWORD, :DWORD
AttachConsole PROTO :DWORD
lstrcmpiA PROTO :DWORD, :DWORD

.data?
    cliArgs CLI_ARGS <>

.code

;; Stub ServerLoop so service.inc links (SvcMain calls it)
ServerLoop PROC wPort:WORD
    ret
ServerLoop ENDP

start:
    invoke ExitProcess, 0
end start
