@echo off
setlocal
echo ========================================================
echo   R3P Agent - Background Auto-Start Setup
echo ========================================================
echo.
echo This script will configure the R3P Agent to start automatically
echo in the background (System Tray) with Administrator privileges
echo every time you log into Windows, avoiding UAC prompts.
echo.

:: Check for Administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] This script must be run as Administrator!
    echo Please right-click and select "Run as administrator".
    echo.
    pause
    exit /b 1
)

:: Define task name and executable path
set TASK_NAME=R3P_Agent_AutoStart
:: Assuming the executable is named R3P_Agent.exe and is in the same folder or dist folder
if exist "%~dp0dist\R3P_Agent.exe" (
    set EXE_PATH="%~dp0dist\R3P_Agent.exe"
) else if exist "%~dp0R3P_Agent.exe" (
    set EXE_PATH="%~dp0R3P_Agent.exe"
) else (
    echo [ERROR] Could not find R3P_Agent.exe in current directory or dist folder.
    echo Please build the agent first using build_collector.bat
    echo.
    pause
    exit /b 1
)

echo Found executable: %EXE_PATH%
echo Creating Scheduled Task...

:: Delete existing task if it exists
schtasks /Delete /TN "%TASK_NAME%" /F >nul 2>&1

:: Create the scheduled task (Highest privileges, trigger on Logon)
schtasks /Create /TN "%TASK_NAME%" /TR %EXE_PATH% /SC ONLOGON /RL HIGHEST /F

if %errorLevel% equ 0 (
    echo.
    echo [SUCCESS] Task created successfully!
    echo The R3P Agent will now start automatically in the system tray when you log in.
) else (
    echo.
    echo [FAILED] Could not create the scheduled task.
)

echo.
pause
exit /b 0
