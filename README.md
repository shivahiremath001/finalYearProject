<p align="center">
  <strong>🛡 R3P — Ransomware Readiness & Risk Profiler</strong>
</p>

<p align="center">
  <em>An intelligent, agent-based platform for continuous ransomware vulnerability assessment, risk scoring, active validation, and automated remediation of Windows endpoints.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue?logo=python" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-0.100+-green?logo=fastapi" alt="FastAPI">
  <img src="https://img.shields.io/badge/React-18+-61DAFB?logo=react" alt="React">
  <img src="https://img.shields.io/badge/SQLite-3-003B57?logo=sqlite" alt="SQLite">
</p>

---

> **Looking for the detailed academic report and internal architecture?** 
> See [`README_DEEP.md`](README_DEEP.md) for in-depth documentation, algorithms, anomaly detection logic, and presentation Q&A.

## What is R3P?

**R3P** is a modern client-server platform designed to continuously assess the ransomware resilience of Windows endpoints. While traditional vulnerability scanners look for known software CVEs, R3P actively scans **configuration drift** and **security posture**—the settings that determine whether ransomware can execute, spread, and prevent recovery.

With Phase 3, R3P also introduces **Active Validation**: it safely executes mock ransomware behaviors (like shadow copy enumeration and rapid mass-file renaming) to test if the endpoint's EDR/AV actually detects and stops the threat.

## Key Features

- 🕵️ **Continuous Telemetry:** Agent-based monitoring of 24+ security parameters across the ransomware kill-chain.
- 🎯 **Active Validation (Mock Attacks):** Safely tests your EDR using benign ransomware behavior simulations.
- 📊 **Risk Scoring & MITRE Mapping:** Each check is scored and mapped to the official MITRE ATT&CK framework.
- 🚨 **Posture Drift Detection:** Statistical rolling z-score anomaly detection identifies sudden security degradation.
- ⚡ **Automated Remediation:** One-click remote fixes for misconfigurations right from the dashboard.
- 🌐 **Real-Time Dashboard:** A gorgeous React-based fleet dashboard with live WebSocket updates.

## Tech Stack

- **Agent:** Python (PyInstaller, PowerShell subsystem)
- **Backend:** FastAPI, SQLAlchemy, SQLite, JWT, WebSockets
- **Frontend:** React 18, Vite, Lucide-React

## Quickstart

### 1. Start the Backend
```bash
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt # (or manually install fastapi uvicorn sqlalchemy pyjwt python-dotenv)
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```
*Note: Ensure you configure your `.env` file with `API_KEY` and `JWT_SECRET`.*

### 2. Start the Frontend
```bash
cd frontend
npm install
npm run dev
```
*Dashboard will run on `http://localhost:5173`.*

### 3. Run the Agent
```bash
# Must be run as Administrator on Windows
python collector.py
```
*You can also run `demo_collector.py` to simulate a fleet of devices sending telemetry.*

## Security

R3P takes agent security seriously. **No arbitrary code ever crosses the network.** Remediation commands are executed via a strict dual-allowlist system, meaning the admin dashboard only sends string keys (e.g., `enable_firewall`), which the agent matches against its own local repository of approved scripts.

---
**License**: Academic / Open-Source
