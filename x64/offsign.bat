@echo off

rem ==========================================================================
rem
rem  OffSign.bat
rem  Author: QINLIU
rem
rem
rem  This tool is used for signing and verification of signatures for VBA projects contained in Office files.
rem
rem  The tool depends on SignTool.exe (from the Windows SDK) being installed and SIPs being registered. Besides,
rem  the tool will call coffclearsig.exe to remove any existing signatures in the currently processed file before
rem  signing, please ensure the offsign.bat and offclearsig.exe are in the same directory.
rem
rem  Paremeters:
rem     1. Signtool.exe file path.
rem     2. Sign command line.
rem     3. Verify command line.
rem     4. filename.
rem
rem  Example:
rem     OffSign.bat "C:\Program Files (x86)\Windows Kits\10\bin\10.0.18362.0\x86\" "sign /f D:\CodeSign.pfx /fd SHA256" "verify /pa" "D:\TestFile.xlsm"
rem ==========================================================================

setlocal

set signtool=signtool.exe
set offclearsig=offclearsig.exe
set helpCmd=help
set ACTION=ERROR
set errNo=0

set E_SIGN_NOT_FOUND="Failed when searching signtool.exe."
set E_CLEAR_NOT_FOUND="Failed when searching offclearsig.exe."
set E_FAIL_CLEARSIG="Failed when executing the clear command."
set E_FAIL_1ST_SIGN="Failed when executing the first sign command."
set E_FAIL_1ST_VERIFY="Failed when executing the first verify command."
set E_FAIL_2ND_SIGN="Failed when executing the second sign command."
set E_FAIL_2ND_VERIFY="Failed when executing the second verify command."
set E_FAIL_3RD_SIGN="Failed when executing the third sign command."
set E_FAIL_3RD_VERIFY="Failed when executing the third verify command."

set ErrNo_SIGN_NOT_FOUND=1
set ErrNo_CLEAR_NOT_FOUND=2
set ErrNo_FAIL_CLEARSIG=3
set ErrNo_FAIL_1ST_SIGN=4
set ErrNo_FAIL_1ST_VERIFY=5
set ErrNo_FAIL_2ND_SIGN=6
set ErrNo_FAIL_2ND_VERIFY=7
set ErrNo_FAIL_3RD_SIGN=8
set ErrNo_FAIL_3RD_VERIFY=9

rem ==========================================================================
rem Receive the three paremeters

set signtoolPath=%1

if %signtoolPath%==%helpCmd% (
	goto LUsage
)

set signtoolPath=%~1
set signCmd=%~2
set verifyCmd=%~3
set fileName=%4

set signCmd=%signCmd% %fileName%
set verifyCmd=%verifyCmd% %fileName%

rem ==========================================================================
rem Find if signtool.exe is located in the specified file path

echo.
echo Finding signtool.exe...
set signtoolPath="%signtoolPath%%signtool%"
IF EXIST %signtoolPath% (
	echo Successfully found the location of signtool.exe:
	echo %signtoolPath%
	goto LFindOffClearSig
)

set ACTION=%E_SIGN_NOT_FOUND%
set errNo=%ErrNo_SIGN_NOT_FOUND%
goto LFail


rem ==========================================================================
rem Find if OffClearSig.exe is located in the same path as OffSign.bat

:LFindOffClearSig

echo.
echo Finding offclearsig.exe...
set offclearsigPath="%~dp0%offclearsig%"
IF EXIST %offclearsigPath% (
	echo Successfully found the location of offclearsig.exe:
	echo %offclearsigPath%
	goto LRunCommand
)

set ACTION=%E_CLEAR_NOT_FOUND%
set errNo=%ErrNo_CLEAR_NOT_FOUND%
goto LFail


rem ==========================================================================
rem Run sign and verify commands

:LRunCommand
echo.
echo ============================ Calling offclearsig command ===========================
echo.
call %offclearsigPath% %fileName% 
if %errorlevel%==0 (
	goto LRun1stSign
) else (
	set ACTION=%E_FAIL_CLEARSIG%
	set errNo=%ErrNo_FAIL_CLEARSIG%
	goto LFail
)

:LRun1stSign
echo.
echo ============================= 1st calling sign command =============================
echo.
call %signtoolPath% %signCmd% 
if %errorlevel%==0 (
	goto LRun1stVerify
) else (
	set ACTION=%E_FAIL_1ST_SIGN%
	set errNo=%ErrNo_FAIL_1ST_SIGN%
	goto LFail
)

:LRun1stVerify
echo.
echo ============================ 1st calling verify command ============================
echo.
call %signtoolPath% %verifyCmd%
if %errorlevel%==0 (
	goto LRun2ndSign
) else (
	set ACTION=%E_FAIL_1ST_VERIFY%
	set errNo=%ErrNo_FAIL_1ST_VERIFY%
	goto LFail
)

:LRun2ndSign
echo.
echo ============================= 2nd calling sign command =============================
echo.
call %signtoolPath% %signCmd%
if %errorlevel%==0 (
	goto LRun2ndVerify
) else (
	set ACTION=%E_FAIL_2ND_SIGN%
	set errNo=%ErrNo_FAIL_2ND_SIGN%
	goto LFail
)

:LRun2ndVerify
echo.
echo ============================ 2nd calling verify command ============================
echo.
call %signtoolPath% %verifyCmd% 
if %errorlevel%==0 (
	goto LRun3rdSign
) else (
	set ACTION=%E_FAIL_2ND_VERIFY%
	set errNo=%ErrNo_FAIL_2ND_VERIFY%
	goto LFail
)

:LRun3rdSign
echo.
echo ============================= 3rd calling sign command =============================
echo.
call %signtoolPath% %signCmd%
if %errorlevel%==0 (
	goto LRun3rdVerify
) else (
	set ACTION=%E_FAIL_3RD_SIGN%
	set errNo=%ErrNo_FAIL_3RD_SIGN%
	goto LFail
)

:LRun3rdVerify
echo.
echo ============================ 3rd calling verify command ============================
echo.
call %signtoolPath% %verifyCmd% 
if %errorlevel%==0 (
	goto LDone
) else (
	set ACTION=%E_FAIL_3RD_VERIFY%
	set errNo=%ErrNo_FAIL_3RD_VERIFY%
	goto LFail
)

:LUsage
echo.
echo OffSign.bat -- signing and verification of signatures for VBA projects contained in Office files.
echo.
echo Usage:
echo     OffSign.bat "Signtool.exe location" "Signing command" "Verify command" "filename"
echo.
echo Example:
echo     OffSign.bat "C:\Program Files (x86)\Windows Kits\10\bin\10.0.18362.0\x86\" "sign /f D:\CodeSign.pfx /fd SHA256" "verify /pa" "D:\TestFile.xlsm"
echo.
echo Error return:
echo     Failed when searching signtool.exe. -------------------1
echo     Failed when searching offclearsig.exe. ----------------2
echo     Failed when executing the clear command. --------------3
echo     Failed when executing the first sign command. ---------4
echo     Failed when executing the first verify command. -------5
echo     Failed when executing the second sign command. --------6
echo     Failed when executing the second verify command. ------7
echo     Failed when executing the third sign command. ---------8
echo     Failed when executing the third verify command. -------9
echo.
goto EOF

:LFail
echo.
echo =================================== Job Summary ====================================
echo Error!
echo %ACTION:"=%
if %ACTION%==%E_SIGN_NOT_FOUND% (
	echo The wrong path:
	echo 	%signtoolPath%
)
if %ACTION%==%E_CLEAR_NOT_FOUND% (
	echo The wrong path:
	echo 	%offclearsigPath%
)
echo You should fix the problem and re-run OffSign.
echo.
goto EOF

:LDone
echo.
echo =================================== Job Summary ====================================
echo Successfully signed and verified file: 
echo 	%fileName%
echo.
goto EOF

:EOF
EXIT /B %errno%
