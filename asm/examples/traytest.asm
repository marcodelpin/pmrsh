.686
.model flat, stdcall
option casemap:none
include tray.inc
ExitProcess PROTO :DWORD
.code
start:
    invoke TrayRun, 9822
    invoke ExitProcess, 0
end start
