@echo off
setlocal enabledelayedexpansion

echo.
echo  pmash Test Suite
echo  ====================
echo.

set "PASS=0"
set "FAIL=0"
:: Build as console for testing (GUI binary needs AttachConsole which doesn't pipe well)
call build.bat src\main -console >nul 2>&1
set "EXE=src\main.exe"
set "PORT=29999"

:: ---- Unit Tests ----
echo [unit] clitest
examples\clitest.exe >nul 2>&1
if !errorlevel! equ 0 (set /a PASS+=1) else (set /a FAIL+=1 & echo   FAIL)
examples\clitest.exe 2>&1 | findstr /C:"FAIL" >nul && (echo   WARNING: some assertions failed)

echo [unit] cryptotest
examples\cryptotest.exe >nul 2>&1
if !errorlevel! equ 0 (set /a PASS+=1) else (set /a FAIL+=1 & echo   FAIL)

echo [unit] exectest
examples\exectest.exe >nul 2>&1
if !errorlevel! equ 0 (set /a PASS+=1) else (set /a FAIL+=1 & echo   FAIL)

echo [unit] netlooptest
examples\netlooptest.exe >nul 2>&1
if !errorlevel! equ 0 (set /a PASS+=1) else (set /a FAIL+=1 & echo   FAIL)

:: ---- E2E Tests ----
echo.
:: Clean auth keys for fresh TOFU test
del "C:\ProgramData\mrsh\client_key" 2>nul
del "C:\ProgramData\mrsh\authorized_keys" 2>nul
del "C:\ProgramData\mrsh\mrsh.log" 2>nul
echo [e2e] Starting server on port %PORT% (TLS+Auth)...
start /b "" "%EXE%" -p %PORT% --console >nul 2>&1
ping -n 8 127.0.0.1 >nul

echo [e2e] ping
"%EXE%" -h 127.0.0.1 -p %PORT% ping 2>&1 | findstr /C:"pong" >nul
if !errorlevel! equ 0 (set /a PASS+=1 & echo   OK) else (set /a FAIL+=1 & echo   FAIL)

echo [e2e] exec hostname
"%EXE%" -h 127.0.0.1 -p %PORT% exec hostname >"%TEMP%\mrsh-test.txt" 2>&1
if !errorlevel! equ 0 (set /a PASS+=1 & echo   OK) else (set /a FAIL+=1 & echo   FAIL)

echo [e2e] exec echo
"%EXE%" -h 127.0.0.1 -p %PORT% exec "echo e2e-test-ok" 2>&1 | findstr /C:"e2e-test-ok" >nul
if !errorlevel! equ 0 (set /a PASS+=1 & echo   OK) else (set /a FAIL+=1 & echo   FAIL)

echo [e2e] info
"%EXE%" -h 127.0.0.1 -p %PORT% info 2>&1 | findstr /C:"hostname" >nul
if !errorlevel! equ 0 (set /a PASS+=1 & echo   OK) else (set /a FAIL+=1 & echo   FAIL)

echo [e2e] ls
"%EXE%" -h 127.0.0.1 -p %PORT% ls C:\ 2>&1 | findstr /C:"PerfLogs" >nul
if !errorlevel! equ 0 (set /a PASS+=1 & echo   OK) else (set /a FAIL+=1 & echo   FAIL)

echo [e2e] version
"%EXE%" --version 2>&1 | findstr /C:"0.1.0" >nul
if !errorlevel! equ 0 (set /a PASS+=1 & echo   OK) else (set /a FAIL+=1 & echo   FAIL)

echo [e2e] screenshot
"%EXE%" -h 127.0.0.1 -p %PORT% screenshot "%TEMP%\mrsh-shot.bmp" 2>&1 | findstr /C:"mrsh-shot.bmp" >nul
if !errorlevel! equ 0 (
    if exist "%TEMP%\mrsh-shot.bmp" (
        for %%F in ("%TEMP%\mrsh-shot.bmp") do (
            if %%~zF gtr 1000 (set /a PASS+=1 & echo   OK ^(%%~zF bytes^)) else (set /a FAIL+=1 & echo   FAIL: too small)
        )
    ) else (set /a FAIL+=1 & echo   FAIL: file not created)
) else (set /a FAIL+=1 & echo   FAIL: no output)
del "%TEMP%\mrsh-shot.bmp" 2>nul

echo [e2e] auth keys created (TOFU)
if exist "C:\ProgramData\mrsh\client_key" (
    if exist "C:\ProgramData\mrsh\authorized_keys" (
        set /a PASS+=1 & echo   OK
    ) else (set /a FAIL+=1 & echo   FAIL: no authorized_keys)
) else (set /a FAIL+=1 & echo   FAIL: no client_key)

echo [e2e] push file
echo push-test-data-12345> "%TEMP%\mrsh-push-src.txt"
"%EXE%" -h 127.0.0.1 -p %PORT% push "%TEMP%\mrsh-push-src.txt" "%TEMP%\mrsh-push-dst.txt" 2>&1 | findstr /C:"push complete" >nul
if !errorlevel! equ 0 (set /a PASS+=1 & echo   OK) else (set /a FAIL+=1 & echo   FAIL)

ping -n 2 127.0.0.1 >nul

echo [e2e] push verify (file exists + non-empty)
if exist "%TEMP%\mrsh-push-dst.txt" (
    for %%F in ("%TEMP%\mrsh-push-dst.txt") do (
        if %%~zF gtr 0 (set /a PASS+=1 & echo   OK ^(%%~zF bytes^)) else (set /a FAIL+=1 & echo   FAIL: 0 bytes)
    )
) else (set /a FAIL+=1 & echo   FAIL: file not found)

echo [e2e] pull file
"%EXE%" -h 127.0.0.1 -p %PORT% pull "%TEMP%\mrsh-push-dst.txt" "%TEMP%\mrsh-pull-out.txt" 2>&1 | findstr /C:"pull complete" >nul
if !errorlevel! equ 0 (set /a PASS+=1 & echo   OK) else (set /a FAIL+=1 & echo   FAIL)

echo [e2e] pull verify (content matches)
fc /B "%TEMP%\mrsh-push-src.txt" "%TEMP%\mrsh-pull-out.txt" >nul 2>&1
if !errorlevel! equ 0 (set /a PASS+=1 & echo   OK) else (set /a FAIL+=1 & echo   FAIL: content mismatch)

echo [e2e] ps (process list)
"%EXE%" -h 127.0.0.1 -p %PORT% ps 2>&1 | findstr /C:"pid" >nul
if !errorlevel! equ 0 (set /a PASS+=1 & echo   OK) else (set /a FAIL+=1 & echo   FAIL)

echo [e2e] write file
echo write-test-content-67890> "%TEMP%\mrsh-write-src.txt"
"%EXE%" -h 127.0.0.1 -p %PORT% write "%TEMP%\mrsh-write-src.txt" "%TEMP%\mrsh-write-dst.txt" 2>&1 | findstr /C:"write complete" >nul
if !errorlevel! equ 0 (set /a PASS+=1 & echo   OK) else (set /a FAIL+=1 & echo   FAIL)

echo [e2e] write verify
if exist "%TEMP%\mrsh-write-dst.txt" (
    fc /B "%TEMP%\mrsh-write-src.txt" "%TEMP%\mrsh-write-dst.txt" >nul 2>&1
    if !errorlevel! equ 0 (set /a PASS+=1 & echo   OK) else (set /a FAIL+=1 & echo   FAIL: content mismatch)
) else (set /a FAIL+=1 & echo   FAIL: file not created)

echo [e2e] mouse pos
"%EXE%" -h 127.0.0.1 -p %PORT% mouse pos 2>&1 | findstr /C:"," >nul
if !errorlevel! equ 0 (set /a PASS+=1 & echo   OK) else (set /a FAIL+=1 & echo   FAIL)

echo [e2e] window list
"%EXE%" -h 127.0.0.1 -p %PORT% window list 2>&1 | findstr /C:"hwnd" >nul
if !errorlevel! equ 0 (set /a PASS+=1 & echo   OK) else (set /a FAIL+=1 & echo   FAIL)

echo [e2e] sync (delta pull)
echo sync-test-original-data-AAAAAA> "%TEMP%\mrsh-sync-local.txt"
echo sync-test-modified-data-BBBBBB> "%TEMP%\mrsh-sync-remote.txt"
:: Push the "remote" file to server first
"%EXE%" -h 127.0.0.1 -p %PORT% push "%TEMP%\mrsh-sync-remote.txt" "%TEMP%\mrsh-sync-srv.txt" >nul 2>&1
ping -n 2 127.0.0.1 >nul
:: Sync: pull delta from server to local
"%EXE%" -h 127.0.0.1 -p %PORT% sync "%TEMP%\mrsh-sync-srv.txt" "%TEMP%\mrsh-sync-local.txt" 2>&1 | findstr /C:"sync complete" >nul
if !errorlevel! equ 0 (
    fc /B "%TEMP%\mrsh-sync-local.txt" "%TEMP%\mrsh-sync-remote.txt" >nul 2>&1
    if !errorlevel! equ 0 (set /a PASS+=1 & echo   OK) else (set /a FAIL+=1 & echo   FAIL: content mismatch)
) else (set /a FAIL+=1 & echo   FAIL: sync failed)

echo [e2e] sync-push (delta push)
echo sync-push-test-data-CCCCCC> "%TEMP%\mrsh-syncpush-src.txt"
"%EXE%" -h 127.0.0.1 -p %PORT% sync-push "%TEMP%\mrsh-syncpush-src.txt" "%TEMP%\mrsh-syncpush-dst.txt" 2>&1 | findstr /C:"sync-push complete" >nul
if !errorlevel! equ 0 (set /a PASS+=1 & echo   OK) else (set /a FAIL+=1 & echo   FAIL)

echo [e2e] kill (self-test with dummy pid)
:: Kill PID 0 should fail gracefully (not crash)
"%EXE%" -h 127.0.0.1 -p %PORT% kill 99999 2>&1 | findstr /C:"kill" >nul
if !errorlevel! equ 0 (set /a PASS+=1 & echo   OK) else (set /a FAIL+=1 & echo   FAIL)

:: Note: shell test requires interactive stdin (skipped in automated suite)
:: Manual test: mrsh -h 127.0.0.1 -p %PORT% shell
::   type "echo shell-ok" → verify output → type "exit" → verify clean exit

:: ---- Cleanup ----
taskkill /IM main.exe /F >nul 2>&1
del "%TEMP%\mrsh-push-src.txt" 2>nul
del "%TEMP%\mrsh-push-dst.txt" 2>nul
del "%TEMP%\mrsh-pull-out.txt" 2>nul
del "%TEMP%\mrsh-write-src.txt" 2>nul
del "%TEMP%\mrsh-write-dst.txt" 2>nul
del "%TEMP%\mrsh-sync-local.txt" 2>nul
del "%TEMP%\mrsh-sync-remote.txt" 2>nul
del "%TEMP%\mrsh-sync-srv.txt" 2>nul
del "%TEMP%\mrsh-syncpush-src.txt" 2>nul
del "%TEMP%\mrsh-syncpush-dst.txt" 2>nul

:: ---- Report ----
echo.
set /a TOTAL=PASS+FAIL
echo  Results: %PASS%/%TOTAL% passed, %FAIL% failed
echo.

if %FAIL% gtr 0 exit /b 1
exit /b 0
