@echo off
setlocal
title volc-sg-sync manager
echo ========================================
echo volc-sg-sync manager
echo ========================================
echo 1. Start
echo 2. Stop
echo 3. Status
echo 4. Uninstall completely (task, process, credentials, files)
echo 0. Exit
set /p CHOICE=Choose an action: 
if "%CHOICE%"=="1" powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0manage.ps1" -Action start
if "%CHOICE%"=="2" powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0manage.ps1" -Action stop
if "%CHOICE%"=="3" powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0manage.ps1" -Action status
if "%CHOICE%"=="4" powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0manage.ps1" -Action uninstall
if "%CHOICE%"=="0" exit /b 0
echo.
pause
