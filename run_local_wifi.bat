@echo off
title R3P Local WiFi Startup Launcher
color 0A

echo ===================================================
echo     R3P System - Local WiFi / Network Launcher
echo ===================================================
echo.

:: 1. Open Firewall Port 8000
echo [1/3] Adding Windows Firewall Rule for Port 8000...
netsh advfirewall firewall add rule name="R3P Backend Port 8000" dir=in action=allow protocol=TCP localport=8000 >nul 2>&1
if %errorlevel% equ 0 (
    echo     [SUCCESS] Port 8000 allowed in Firewall.
) else (
    echo     [NOTE] Could not auto-add firewall rule. If other devices cannot connect, run this script as Administrator.
)

:: 2. Retrieve Local IP Address
echo.
echo [2/3] Detecting Local IPv4 Address...
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"IPv4 Address"') do (
    set LOCAL_IP=%%a
)
:: Trim leading space
if defined LOCAL_IP set LOCAL_IP=%LOCAL_IP:~1%

echo     ---------------------------------------------------
echo     Your Host Machine IP Address: %LOCAL_IP%
echo     ---------------------------------------------------

:: 3. Launch Backend
echo.
echo [3/3] Starting Backend & Frontend Services...
echo     - Starting FastAPI Backend on 0.0.0.0:8000...
start "R3P Backend Server (LAN)" cmd /k "cd backend && call venv\Scripts\activate && uvicorn main:app --reload --host 0.0.0.0 --port 8000"

:: 4. Launch Frontend exposed to network
echo     - Starting Vite Frontend on 0.0.0.0:5173...
start "R3P Frontend Server (LAN)" cmd /k "cd frontend && npm run dev -- --host"

echo.
echo ===================================================
echo               SERVICES LAUNCHED!
echo ===================================================
echo.
echo  - Host Backend URL  : http://localhost:8000 or http://%LOCAL_IP%:8000
echo  - Host Frontend URL : http://localhost:5173
echo  - Wi-Fi Network URL : http://%LOCAL_IP%:5173
echo.
echo  - Connect Agents from other Wi-Fi devices using:
echo    python collector.py --server http://%LOCAL_IP%:8000
echo.
echo Keep the opened command windows running!
echo ===================================================
echo.
pause
