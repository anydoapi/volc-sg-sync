@echo off
setlocal
title volc-sg-sync installer
echo ========================================
echo volc-sg-sync installer
echo ========================================
echo Starting installer and requesting administrator permission...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
set "EXITCODE=%ERRORLEVEL%"
echo.
if "%EXITCODE%"=="0" (
  echo [SUCCESS] Installation completed.
  echo Web console: http://127.0.0.1:12345
) else (
  echo [FAILED] Installation failed with code %EXITCODE%.
  echo Review the error messages above.
)
echo.
pause
exit /b %EXITCODE%
