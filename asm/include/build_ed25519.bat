@echo off
setlocal
set "VCTOOLS=s:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\MSVC\14.50.35717"
set "SDKINC=C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0"
set "CL=%VCTOOLS%\bin\Hostx86\x86\cl.exe"
"%CL%" /c /O2 /nologo /W3 /Oi- /Gs- /Zl /I"%VCTOOLS%\include" /I"%SDKINC%\ucrt" /I"%SDKINC%\um" /I"%SDKINC%\shared" ed25519_wrap.c tweetnacl.c
if errorlevel 1 (echo FAILED & exit /b 1)
echo OK: ed25519_wrap.obj + tweetnacl.obj
