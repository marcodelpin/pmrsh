@echo off
setlocal enabledelayedexpansion

:: =============================================================================
:: build.bat — Build MASM programs with GRC-style linking (no CRT)
::
:: Usage:  build examples\hello          Build as GUI app
::         build examples\hello -console Build as console app
::         build                         Build examples\hello (default)
:: =============================================================================

:: ---- Find MASM via vswhere ----
set "ML="
set "VSWHERE=C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
    for /f "delims=" %%I in ('"%VSWHERE%" -latest -property installationPath 2^>nul') do (
        set "VSDIR=%%I"
    )
)
if defined VSDIR (
    for /d %%V in ("!VSDIR!\VC\Tools\MSVC\*") do (
        if exist "%%V\bin\Hostx86\x86\ml.exe" (
            set "MLDIR=%%V\bin\Hostx86\x86"
            set "LIBPATH=%%V\lib\x86"
        )
    )
)

:: ---- Find Windows SDK (libs + rc.exe) ----
set "SDKLIB="
set "RCDIR="
for /d %%S in ("C:\Program Files (x86)\Windows Kits\10\Lib\*") do (
    if exist "%%S\um\x86\kernel32.lib" set "SDKLIB=%%S\um\x86"
)
for /d %%S in ("C:\Program Files (x86)\Windows Kits\10\bin\*") do (
    if exist "%%S\x86\rc.exe" set "RCDIR=%%S\x86"
)

if not defined MLDIR (
    echo ERROR: ml.exe not found. Install Visual Studio Build Tools with C++ workload.
    exit /b 1
)
if not defined SDKLIB (
    echo ERROR: Windows SDK not found.
    exit /b 1
)

:: ---- Parse arguments ----
set "INPUT=%~1"
if "%INPUT%"=="" set "INPUT=examples\hello"
set "NAME=%~n1"
if "%NAME%"=="" set "NAME=hello"
set "SUBSYSTEM=WINDOWS"
if /i "%~2"=="-console" set "SUBSYSTEM=CONSOLE"

set "ASMFILE=%INPUT%.asm"
set "EXEFILE=%INPUT%.exe"

echo.
echo  MASM Toolkit Builder
echo  ====================
echo  Source:    %ASMFILE%
echo  Target:    %EXEFILE%
echo  Subsystem: %SUBSYSTEM%
echo.

:: ---- Assemble ----
echo [1/3] Assembling...
"!MLDIR!\ml.exe" /c /coff /nologo /I. /Iinclude "%ASMFILE%"
if errorlevel 1 (
    echo FAILED: Assembly errors.
    exit /b 1
)

:: ml.exe puts .obj in CWD with source basename
set "OBJFILE=%NAME%.obj"
set "RESFILE="

:: ---- Compile resources (if .rc exists) ----
set "RCFILE=!INPUT!.rc"
if exist "!RCFILE!" (
    if defined RCDIR (
        echo [2/3] Compiling resources...
        for %%R in ("!RCFILE!") do (
            pushd "%%~dpR"
            "!RCDIR!\rc.exe" /nologo /fo "%%~nR.res" "%%~nR.rc"
            popd
        )
        if errorlevel 1 (
            echo FAILED: Resource compilation errors.
            exit /b 1
        )
        set "RESFILE=!INPUT!.res"
    ) else (
        echo WARNING: rc.exe not found, skipping resources.
    )
) else (
    echo [2/3] No .rc file, skipping resources.
)

:: ---- Link (no CRT) ----
echo [3/3] Linking...
"!MLDIR!\link.exe" /NOLOGO /SUBSYSTEM:%SUBSYSTEM% /ENTRY:start ^
    /NODEFAULTLIB:OLDNAMES ^
    "/LIBPATH:!LIBPATH!" "/LIBPATH:!SDKLIB!" ^
    kernel32.lib user32.lib gdi32.lib comctl32.lib ws2_32.lib advapi32.lib shell32.lib bcrypt.lib secur32.lib crypt32.lib ntdll.lib shlwapi.lib libcmt.lib ^
    "%OBJFILE%" include\ed25519_wrap.obj include\tweetnacl.obj !RESFILE! "/OUT:%EXEFILE%"
if errorlevel 1 (
    echo FAILED: Link errors.
    exit /b 1
)

:: ---- Report ----
for %%F in ("%EXEFILE%") do set "SIZE=%%~zF"
echo.
echo  OK: %EXEFILE% (!SIZE! bytes)
echo.

:: Cleanup
del "%OBJFILE%" 2>nul

endlocal
