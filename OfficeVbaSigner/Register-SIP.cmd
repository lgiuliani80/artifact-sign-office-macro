@echo off
:: Register OfficeSIP native DLLs (requires Administrator privileges)
:: Run this script from the directory containing the DLLs.

echo Registering Office SIP DLLs...
echo.

set "REGSVR=%SystemRoot%\SysWOW64\regsvr32.exe"
if not exist "%REGSVR%" set "REGSVR=%SystemRoot%\System32\regsvr32.exe"

echo Using: %REGSVR%
echo.

%REGSVR% /s "%~dp0msosip.dll"
if %errorlevel% equ 0 (echo   msosip.dll  - OK) else (echo   msosip.dll  - FAILED [%errorlevel%])

%REGSVR% /s "%~dp0msosipx.dll"
if %errorlevel% equ 0 (echo   msosipx.dll - OK) else (echo   msosipx.dll - FAILED [%errorlevel%])

echo.
echo Done. SIPs registered for VBA macro signing.
pause
