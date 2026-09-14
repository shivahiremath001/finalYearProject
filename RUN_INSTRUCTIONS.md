# How to Run the Project

This project consists of a Python backend, a Node.js frontend, and uses **Ngrok** to create a secure tunnel for the backend API.

## 1. Quick Start (Recommended - Docker)
The absolute easiest and most robust way to run the project is using Docker. This ensures you do not run into Python or Node version conflicts.

1. Open a terminal in the root directory.
2. Run: `docker-compose up -d --build`
3. The dashboard will be instantly available at `http://localhost:5173`.

---

## 2. Windows Batch File Start
You can also simply double-click the `run_project.bat` file located in this directory. It will automatically open three separate terminal windows to run the frontend, the backend, and the ngrok tunnel locally.

## Manual Start

If you prefer to start them manually, follow these steps:

### 1. Start the Backend
Open a terminal and run the following commands:
```cmd
cd backend
venv\Scripts\activate
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```
*The backend will be available at http://localhost:8000*

### 2. Start the Frontend
Open a **new, separate** terminal window and run:
```cmd
cd frontend
npm install
npm run dev
```
*The frontend will display its local URL in the terminal (usually http://localhost:5173).*

### 3. Start the Ngrok Tunnel
Since the frontend uses a specific ngrok domain to communicate with the backend, you must also start the ngrok tunnel.
Open a **third, separate** terminal window and run:
```cmd
ngrok http --url=sleep-abnormal-sputter.ngrok-free.dev 8000
```
*This maps your backend (port 8000) to `https://sleep-abnormal-sputter.ngrok-free.dev`.*
