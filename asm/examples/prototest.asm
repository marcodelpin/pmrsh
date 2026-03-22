.686
.model flat, stdcall
option casemap:none
include net.inc
include tls.inc
include crypto.inc
include proto.inc
RtlMoveMemory PROTO :DWORD, :DWORD, :DWORD
ExitProcess   PROTO :DWORD
.code
start:
    invoke ExitProcess, 0
end start
