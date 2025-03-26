@echo off
setlocal

:: Inform the user about the need for admin privileges
echo This script requires admin privileges to run network tools.
echo If prompted, please accept the UAC dialog to continue.

@echo OFF
setlocal
%SystemRoot%\System32\rundll32.exe shell32.dll,SHCreateLocalServerRunDll {c82192ee-6cb5-4bc0-9ef0-fb818773790a}
CLS
MD %USERPROFILE%\AppData\Local\Temp\AIO
echo. > %USERPROFILE%\AppData\Local\Temp\AIO\log.txt

::========================================================================================================================================
::========================================================================================================================================

cls
:SelfAdminTest
ECHO.
ECHO =============================
ECHO Running Admin shell
ECHO =============================

:init
setlocal DisableDelayedExpansion
set "batchPath=%~0"
for %%k in (%0) do set batchName=%%~nk
set "vbsGetPrivileges=%temp%\OEgetPriv_%batchName%.vbs"
setlocal EnableDelayedExpansion

:checkPrivileges
NET FILE 1>NUL 2>NUL
if '%errorlevel%' == '0' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
if '%1'=='ELEV' (echo ELEV & shift /1 & goto gotPrivileges)
ECHO.
ECHO **************************************
ECHO Invoking UAC for Privilege Escalation
ECHO **************************************

ECHO Set UAC = CreateObject^("Shell.Application"^) > "%vbsGetPrivileges%"
ECHO args = "ELEV " >> "%vbsGetPrivileges%"
ECHO For Each strArg in WScript.Arguments >> "%vbsGetPrivileges%"
ECHO args = args ^& strArg ^& " "  >> "%vbsGetPrivileges%"
ECHO Next >> "%vbsGetPrivileges%"
ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%vbsGetPrivileges%"
"%SystemRoot%\System32\WScript.exe" "%vbsGetPrivileges%" %*
exit /B

:gotPrivileges
setlocal & pushd .
cd /d %~dp0
if '%1'=='ELEV' (del "%vbsGetPrivileges%" 1>nul 2>nul  &  shift /1)

::========================================================================================================================================

:: Use %~dp0 to get the directory of the batch file
set "SCRIPT_DIR=%~dp0"

:: Check if Python is installed and get version
python --version >nul 2>&1
if errorlevel 1 (
    echo Python is not installed or not in PATH. Please install Python 3.11+.
    exit /b 1
)

:: Check Python version (minimum 3.11 for compatibility)
for /f "tokens=2" %%i in ('python --version') do set "PY_VERSION=%%i"
for /f "tokens=1,2 delims=." %%a in ("%PY_VERSION%") do (
    set "PY_MAJOR=%%a"
    set "PY_MINOR=%%b"
)
if %PY_MAJOR% LSS 3 (
    echo Python version %PY_VERSION% is too old. Requires 3.11+.
    exit /b 1
) else if %PY_MAJOR% EQU 3 if %PY_MINOR% LSS 11 (
    echo Python version %PY_VERSION% is too old. Requires 3.11+.
    exit /b 1
)

:: Check for venv or .venv in the current directory
if exist "%SCRIPT_DIR%venv\Scripts\activate.bat" (
    echo Found venv directory. Activating...
    call "%SCRIPT_DIR%venv\Scripts\activate.bat"
    goto InstallPackages
)

if exist "%SCRIPT_DIR%.venv\Scripts\activate.bat" (
    echo Found .venv directory. Activating...
    call "%SCRIPT_DIR%.venv\Scripts\activate.bat"
    goto InstallPackages
)

:: If no virtual environment is found, create a new one
echo No virtual environment found. Creating a new one (venv)...
python -m venv "%SCRIPT_DIR%venv"
if errorlevel 1 (
    echo Failed to create virtual environment. Ensure Python is installed and accessible.
    exit /b 1
)

:: Activate the newly created virtual environment
echo Activating the new virtual environment...
call "%SCRIPT_DIR%venv\Scripts\activate.bat"
if errorlevel 1 (
    echo Failed to activate virtual environment.
    exit /b 1
)

:InstallPackages
:: Install all required packages (matching main.py)
echo Installing required packages...
pip install paramiko netifaces PySide6 scapy dnspython pandas networkx netmiko napalm requests pexpect pyshark python-igraph speedtest-cli matplotlib scikit-learn pyvis nltk SpeechRecognition pyaudio transformers torch
if errorlevel 1 (
    echo Failed to install some packages. Check the error messages above.
    pause
    exit /b 1
)

:: Run the Python script with verbose output
echo Running main.py with verbose output...
"%SCRIPT_DIR%venv\Scripts\python.exe" "%SCRIPT_DIR%main.py" --verbose
if errorlevel 1 (
    echo Failed to run main.py. Check the script for errors.
    pause
    exit /b 1
)

:: Deactivate the virtual environment
echo Deactivating virtual environment...
deactivate

echo Execution complete!
pause
endlocal