@echo off
setlocal DisableDelayedExpansion
pushd "%~dp0" || exit /b 1
if not exist "bootstrap-windows.ps1" (
    echo Extract the complete PacketScope ZIP, then open Start-PacketScope.cmd.
    pause
    exit /b 1
)
set "ps=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe" set "ps=%SystemRoot%\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
"%ps%" -NoProfile -ExecutionPolicy Bypass -File ".\bootstrap-windows.ps1" %*
set "result=%errorlevel%"
if not "%result%"=="0" pause
popd
exit /b %result%
