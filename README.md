<p align="center">
  <strong>🛡 R3P — Ransomware Readiness &amp; Risk Profiler</strong>
</p>

<p align="center">
  <em>An intelligent, agent-based platform for continuous ransomware vulnerability assessment, explainable risk scoring, active validation, deception-based attack detection, and automated remediation of Windows endpoints.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue?logo=python" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-0.100+-green?logo=fastapi" alt="FastAPI">
  <img src="https://img.shields.io/badge/React-18+-61DAFB?logo=react" alt="React">
  <img src="https://img.shields.io/badge/SQLite-3%20(WAL)-003B57?logo=sqlite" alt="SQLite">
  <img src="https://img.shields.io/badge/Tests-19%20Passed-brightgreen" alt="Tests">
</p>

---

> **Looking for deep academic documentation, formulas, and viva defense Q&A?**  
> - 📖 **[README_DEEP.md](README_DEEP.md)** — Exhaustive architecture, mathematical formulations, anomaly statistics, honeytoken design, and parameter matrix.  
> - 🎓 **[docs/VIVA_NOTES.md](docs/VIVA_NOTES.md)** — Presentation defense guide, examiner questions, and project limitations.  
> - 📝 **[CHANGELOG_R3P.md](CHANGELOG_R3P.md)** — Step-by-step engineering changelog for T1–T6 and beyond.

---

## What is R3P?

**R3P** is a modern client-server platform designed to continuously assess the ransomware resilience of Windows endpoints. While traditional vulnerability scanners look for known software CVEs, R3P actively audits **configuration drift** and **security posture**—the settings that determine whether ransomware can execute, spread laterally, steal credentials, and destroy recovery backups.

R3P also incorporates:
- **Active Behavioral Validation**: safe, non-destructive mock ransomware simulations (VSS shadow copy enumeration and dual-probe rapid mass-file renaming targeting protected folders) to verify whether local endpoint protection (EDR/AV, Windows Defender Controlled Folder Access) actively intercepts and halts ransomware behavior in real time.
- **Deception Technology (Honeytoken Canary Subsystem)**: a background filesystem canary trap that deploys a hidden bait file (`!0000_financial_records.docx`) in `C:\Users\Public\Documents`. Any modification or renaming of this canary file by an unauthorized process triggers an immediate `CRITICAL` alert (100/100 risk score) surfaced to the dashboard, flagging real attacker presence distinct from misconfiguration risk.

---

## Key Features

- 🕵️ **Continuous Telemetry:** Windows agent collecting 27 low-level security parameters across the ransomware attack chain (WMI, Registry, PowerShell, CIM).
- 🔑 **Immutable Hardware Identity:** Triple-tier identity resolution based on Windows Cryptography `MachineGuid` and BIOS UUID, preventing duplicate fleet registration during DHCP IP roaming or Wi-Fi/Ethernet interface switching.
- 🎯 **Dual-Probe Active Behavioral Validation:** 
  - *Probe 1 (Protected Folder Ransomware Attack — MITRE T1486):* Safely targets user library space with `.locked` file alterations to test whether Windows Defender Controlled Folder Access (CFA) or EDR actively blocks the attack at runtime (Event ID 1123).
  - *Probe 2 (Rapid Mass-Rename Burst):* Tests behavioral velocity heuristics across 100 batch operations.
- 📊 **Dynamic, Explainable Risk Scoring:** Computes a normalized 0–100 risk score dynamically derived from active weights ($S \times L \times C_{asset}$) with top-factor score explanations (`/machines/{id}/score-explanation`).
- 🚨 **Consistent Active-Test Escalation:** When a mock attack succeeds, the effective risk score is raised to at least 75/100 so its numeric score agrees with the CRITICAL classification; detailed weighted findings remain available separately.
- 🚨 **Statistical Posture Drift Detection:** Rolling Z-score anomaly detector with variance floor ($\sigma_{eff} = \max(\sigma, 1.0)$) and remediation drop suppression.
- ⏱️ **Automatic Agent Offline Detection:** Background server daemon monitoring heartbeat timestamps (`last_seen > 150s`) to mark disconnected nodes.
- ⚡ **Controlled Remote Remediation:** Admin-confirmed fixes use server and agent allowlists; the agent rescans immediately afterward so the dashboard can verify the observed configuration.
- 🍯 **Deception Technology — Honeytoken Canary Subsystem (MITRE T1486/T1491):** Hidden bait file deployed in `C:\Users\Public\Documents`; a daemon thread polls integrity every 2s. Unauthorised rename triggers `honeypot_triggered=true`, bypassing weighted scoring and instantly setting risk to **100/100 CRITICAL** with a dedicated `Active Attack` kill-chain phase in the dashboard.
- 🧭 **Multi-OS Guided Manual Remediation:** Comprehensive, tabbed remediation guides covering **Windows 11, Windows 10, and Windows Server** across all 27 findings with step-by-step GUI instructions, copy-paste PowerShell commands with one-click clipboard copying, post-fix verification, and operational cautions.
- 🔬 **Sensitivity & Validation Benchmark Suite:** Monte Carlo weight perturbation analysis and synthetic archetype validation (`analysis/`).
- 🌐 **Real-Time Fleet Dashboard:** React 18 single-page application with live WebSocket event streaming, risk analytics, and network topology visualization.

### Remote and Manual Fixes

R3P currently offers remote fixes for 17 settings: SMBv1, exposed RDP, USB AutoRun, PowerShell execution policy, UAC, Defender real-time protection, Windows Firewall, Defender Tamper Protection (best effort), Event Log, Guest account, LSASS protection, WDigest, RDP Network Level Authentication, AlwaysInstallElevated, the vulnerable-driver blocklist, HVCI, and one ASR rule. Administrators confirm a fix before it is queued. The confirmation highlights relevant risks, and the agent runs a fresh scan after execution; command completion alone is not treated as proof that protection is active.

### Preparing a Windows Endpoint for a Mock-Attack Demo

Run the collector on a disposable Windows 10/11 test VM with the endpoint protection product and policies you intend to demonstrate enabled. Run the collector elevated so permission failures are less likely to be mistaken for security blocking, and take a VM snapshot before making configuration changes. Do not turn off Defender or tamper protection, add exclusions, or weaken organizational policy just to force a mock test to pass or fail.

The VSS test performs a read-only inventory query, which Windows commonly permits. The mass-rename test uses a **Dual-Probe Validation Architecture**: Probe 1 targets user document space with an unauthorized create/rename (`.locked`) to trigger Windows Defender Controlled Folder Access (CFA Event ID 1123) or EDR hooks, while Probe 2 tests behavioral velocity heuristics across 100 batch operations in temporary space. A successful result means the action was allowed without defensive interception. When Controlled Folder Access is enabled (`Set-MpPreference -EnableControlledFolderAccess Enabled`), Defender actively intercepts the mock file manipulation and the agent registers the attack as **BLOCKED**.

RDP disablement and Tamper Protection also include manual guidance: disabling RDP can cut off administration, and the Tamper Protection command is best effort, so verify it through Windows Security or the organization’s Defender/Intune policy. Other organization-dependent settings (such as backups, BitLocker recovery-key escrow, AppLocker, LAPS, and EDR behavior rules) show tailored multi-OS guidance (Windows 11, Windows 10, Windows Server). The PowerShell execution-policy action is labeled as defense in depth: it is not a security boundary.

If agents are distributed as compiled executables, rebuild the agent from the updated `collector.py` and redeploy it to receive the in-app multi-OS fix guide and current remediation behavior.

---

## Tech Stack

- **Agent:** Python 3.10+ (Win32 APIs, WMI, PowerShell subsystem, ctypes, pystray, PyInstaller)
- **Backend:** FastAPI, SQLAlchemy, SQLite (WAL mode), Pydantic, WebSockets
- **Frontend:** React 18, Vite, Lucide-React, Chart.js
- **Analysis & Testing:** PyTest, Pandas, Matplotlib, Scipy, Tabulate
- **Deployment:** PyInstaller (standalone `.exe`), Ngrok (public tunnel), Docker Compose

---

## Getting Started

### 1. Local Development (Recommended)

#### A. Start the Backend API
```powershell
# In root or backend directory:
pip install -r requirements.txt
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```
* Backend Swagger API Docs: `http://localhost:8000/docs`

#### B. Start the Frontend Dashboard
```powershell
cd frontend
npm install
npm run dev
```
* Web Dashboard: `http://localhost:5173`

#### C. Run the Endpoint Collector Agent
```powershell
# Must be run with Administrator privileges on Windows
python collector.py
```
*(Optional: Run `python demo_collector.py` to simulate telemetry across multiple virtual machines).*

---

### 2. One-Click Local Network Start (Same Wi-Fi)

```powershell
# Right-click → Run as Administrator:
run_local_wifi.bat
```
Detects your host IPv4, opens firewall port 8000, and starts both backend and frontend servers.  
Connect agent machines on the same Wi-Fi using: `http://<HOST_IP>:8000`

---

### 3. Public Internet / Remote Deployment (Ngrok Tunnel)

```powershell
# Starts backend, frontend, and Ngrok tunnel:
run_project.bat
```
* Public Ngrok URL: `https://sleep-abnormal-sputter.ngrok-free.dev` (routed to backend port 8000)
* Agent on remote machines uses this URL stored in `r3p_server.txt`.

---

### 4. Build Standalone Agent Executable

To build a standalone `R3P_Agent.exe` (no Python required on target machine):

```powershell
# Double-click or run from project folder:
build_collector.bat
```
Output: `dist\R3P_Agent.exe`

**Deploy to other machines:**
1. Copy `dist\R3P_Agent.exe` (and optionally `r3p_server.txt`) to the target PC.
2. Right-click `R3P_Agent.exe` → **Run as Administrator**.
3. On first launch without `r3p_server.txt`, a setup dialog prompts for the server IP or Ngrok URL, which is saved automatically.

#### Optional: Auto-Start on Boot (Target Machine)
```powershell
# On target machine, right-click → Run as Administrator:
setup_agent.bat
```
Registers `R3P_Agent.exe` as a Windows Scheduled Task that launches automatically on user logon with highest privileges.

---

### 5. Docker Compose Deployment

```powershell
# Start frontend and backend in isolated containers
docker-compose up -d --build
```
* Dashboard: `http://localhost:5173` | API: `http://localhost:8000`

---

## Agent Configuration Files

The agent reads two configuration files located **in the same folder as the executable**:

| File | Purpose | Behavior |
|---|---|---|
| `r3p_server.txt` | Stores the server URL/IP address | Created on first run via setup dialog. Delete to reset and re-prompt. |
| `agent_config.json` | Optional override: `api_key`, `scan_interval_seconds`, `command_poll_enabled`, `asset_type` | Defaults used if file absent. |

---

## Deployment Workflow Summary

| Step | File | Action |
|---|---|---|
| **1a. Start Server (LAN)** | `run_local_wifi.bat` | Starts backend + frontend on local Wi-Fi |
| **1b. Start Server (Internet)** | `run_project.bat` | Starts backend + frontend + Ngrok tunnel |
| **2. Build Agent EXE** | `build_collector.bat` | Compiles `collector.py` → `dist\R3P_Agent.exe` |
| **3. Deploy to Endpoint** | Copy `R3P_Agent.exe` + `r3p_server.txt` | Run as Administrator on target machine |
| **4. (Optional) Auto-Start** | `setup_agent.bat` | Registers agent as Windows Scheduled Task on boot |

---

## Testing & Validation Suite

Run automated unit and integration tests (Scoring, Dynamic $Risk_{max}$, Heartbeat Monitor, Machine Identity Persistence, Anomaly Detector):

```powershell
# Run the test suite (19 passed)
pytest backend/tests -v
```

Run statistical sensitivity and synthetic benchmark models:

```powershell
# 1,000-run Monte Carlo Weight Sensitivity Analysis
python analysis/sensitivity.py

# Synthetic Archetype Score Ordering Validation
python analysis/validate.py
```
*Analysis outputs (markdown tables, CSVs, distribution charts) are saved in `analysis/output/`.*

---

## Security Model

R3P uses an allowlist-based remote execution model. No arbitrary code or dynamic scripts are transmitted across the network. An administrator confirms a fix in the dashboard; the backend queues a pre-approved command key, and the agent checks that key against its local allowlist before executing PowerShell. The agent then performs a fresh scan so the dashboard can compare the resulting configuration. This verification is separate from the command execution acknowledgment.

## Windows Agent & Web Multi-OS Fix Guides

Both the React Web Dashboard and the Tkinter endpoint agent expose a searchable, categorized **Multi-OS Fix Guide** directory across all 27 findings. Each guide provides dedicated tabs for **Windows 11**, **Windows 10**, and **Windows Server**, including:
1. **Step-by-Step GUI Navigation:** Version-specific paths for Windows Security, Settings app, Control Panel, and Server Manager.
2. **PowerShell CLI Command:** Hardened, ready-to-run administrative PowerShell command with a one-click clipboard copy button (`📋 Copy Command`).
3. **Verification Command:** Standalone PowerShell query to confirm the setting is actively applied.
4. **Operational Cautions:** Highlighting administrator requirements, service dependencies, reboot prerequisites, and domain Group Policy overrides.

The active validation probes execute real-world behavior to test defensive containment. The VSS probe executes a read-only inventory query to check for reconnaissance protection. The mass-rename probe uses a dual-probe method (user document library probe + batch temporary burst) to test whether Windows Defender Controlled Folder Access or behavioral EDR intercepts unauthorized file changes. When CFA is enabled, Defender logs Event ID 1123 and blocks the operation, marking the active validation as defended.

When the server cannot be reached, the agent still displays the current scan's locally identified findings and offers the relevant guidance. It marks these results **LOCAL SCAN / NOT SYNCED**. The risk score is not calculated offline because server policy exceptions are unavailable; the dashboard score and exception handling resume when telemetry reaches the server.

---
**License**: Academic / Open-Source Project
