.686
.model flat, stdcall
option casemap:none
include net.inc
include exec.inc
include service.inc
ExitProcess PROTO :DWORD
.code
start:
    invoke ExitProcess, 0
end start
