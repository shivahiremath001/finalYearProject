@echo off
echo ===================================================
echo Starting Final Project Application
echo ===================================================

echo.
echo Starting Backend (FastAPI)...
start "Backend Server" cmd /k "cd backend && call venv\Scripts\activate && uvicorn main:app --reload --host 0.0.0.0 --port 8000"

echo.
echo Starting Frontend (Vite/React)...
start "Frontend Server" cmd /k "cd frontend && npm install && npm run dev"

echo.
echo Starting Ngrok Tunnel...
start "Ngrok Tunnel" cmd /k "ngrok http --url=sleep-abnormal-sputter.ngrok-free.dev 8000"

echo.
echo All components are starting in separate windows!
echo - Backend: http://localhost:8000
echo - Frontend: Local URL shown in its terminal (e.g. http://localhost:5173)
echo - Ngrok Tunnel: https://sleep-abnormal-sputter.ngrok-free.dev (routing to Backend)
echo.
pause
