@echo off
setlocal
title R3P Agent - Build Script

echo ============================================================
echo   R3P Agent - PyInstaller Build
echo ============================================================
echo.
echo This will create a standalone R3P_Agent.exe that can be
echo copied to ANY Windows machine (no Python required).
echo.

REM ── Step 1: Install dependencies ─────────────────────────────
echo [1/3] Installing dependencies...
pip install pyinstaller requests --quiet
if errorlevel 1 (
    echo ERROR: pip install failed. Make sure Python + pip are in PATH.
    pause
    exit /b 1
)
echo       Done.
echo.

REM ── Step 2: Build the .exe ────────────────────────────────────
echo [2/3] Building R3P_Agent.exe (this may take 30-60 seconds)...
pyinstaller ^
    --onefile ^
    --windowed ^
    --uac-admin ^
    --name R3P_Agent ^
    --hidden-import=tkinter ^
    --hidden-import=tkinter.ttk ^
    collector.py

if errorlevel 1 (
    echo.
    echo ERROR: PyInstaller build failed. Check the output above.
    pause
    exit /b 1
)

REM ── Step 3: Done ─────────────────────────────────────────────
echo.
echo [3/3] Build complete!
echo.
echo ============================================================
echo   Output: dist\R3P_Agent.exe
echo ============================================================
echo.
echo HOW TO DEPLOY:
echo   1. Copy  dist\R3P_Agent.exe  to the target Windows machine
echo   2. Double-click it (accept the UAC admin prompt)
echo   3. First run: enter your server IP address
echo   4. The app scans and sends results automatically
echo.
echo   To reset the saved server IP on a target machine:
echo   Delete  r3p_server.txt  in the same folder as the .exe
echo.

REM Open the dist folder
explorer dist

pause
