<p align="center">
  <strong>🛡 R3P — Ransomware Readiness & Risk Profiler</strong>
</p>

<p align="center">
  <em>An intelligent, agent-based platform for continuous ransomware vulnerability assessment, explainable risk scoring, active validation, and automated remediation of Windows endpoints.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue?logo=python" alt="Python">
  <img src="https://img.shields.io/badge/FastAPI-0.100+-green?logo=fastapi" alt="FastAPI">
  <img src="https://img.shields.io/badge/React-18+-61DAFB?logo=react" alt="React">
  <img src="https://img.shields.io/badge/SQLite-3%20(WAL)-003B57?logo=sqlite" alt="SQLite">
  <img src="https://img.shields.io/badge/Tests-17%20Passed-brightgreen" alt="Tests">
</p>

---

> **Looking for deep academic documentation, formulas, and viva defense Q&A?**  
> - 📖 **[README_DEEP.md](README_DEEP.md)** — Exhaustive architecture, mathematical formulations, anomaly statistics, and parameter matrix.  
> - 🎓 **[docs/VIVA_NOTES.md](docs/VIVA_NOTES.md)** — Presentation defense guide, examiner questions, and project limitations.  
> - 📝 **[CHANGELOG_R3P.md](CHANGELOG_R3P.md)** — Step-by-step engineering changelog for T1–T5 and beyond.

---

## What is R3P?

**R3P** is a modern client-server platform designed to continuously assess the ransomware resilience of Windows endpoints. While traditional vulnerability scanners look for known software CVEs, R3P actively audits **configuration drift** and **security posture**—the settings that determine whether ransomware can execute, spread laterally, steal credentials, and destroy recovery backups.

R3P also incorporates **Active Behavioral Validation**: safe, non-destructive mock ransomware simulations (such as VSS shadow copy enumeration and rapid mass-file renaming) to verify whether local endpoint protection (EDR/AV) actively detects and stops ransomware behavior.

---

## Key Features

- 🕵️ **Continuous Telemetry:** Windows agent collecting 27 low-level security parameters across the ransomware attack chain (WMI, Registry, PowerShell, CIM).
- 🎯 **Active Behavioral Probes:** Runs a read-only VSS inventory query and temporary-file rename probe; these show whether those exact benign actions were allowed.
- 📊 **Dynamic, Explainable Risk Scoring:** Computes a normalized 0–100 risk score dynamically derived from active weights ($S \times L \times C_{asset}$) with top-factor score explanations (`/machines/{id}/score-explanation`).
- 🚨 **Consistent Active-Test Escalation:** When a mock attack succeeds, the effective risk score is raised to at least 75/100 so its numeric score agrees with the CRITICAL classification; detailed weighted findings remain available separately.
- 🚨 **Statistical Posture Drift Detection:** Rolling Z-score anomaly detector with variance floor ($\sigma_{eff} = \max(\sigma, 1.0)$) and remediation drop suppression.
- ⏱️ **Automatic Agent Offline Detection:** Background server daemon monitoring heartbeat timestamps (`last_seen > 150s`) to mark disconnected nodes.
- ⚡ **Controlled Remote Remediation:** Admin-confirmed fixes use server and agent allowlists; the agent rescans immediately afterward so the dashboard can verify the observed configuration.
- 🧭 **Guided Manual Remediation:** Risks without a safe agent command show parameter-specific steps and verification guidance in the system detail view.
- 🔬 **Sensitivity & Validation Benchmark Suite:** Monte Carlo weight perturbation analysis and synthetic archetype validation (`analysis/`).
- 🌐 **Real-Time Fleet Dashboard:** React 18 single-page application with live WebSocket event streaming, risk analytics, and network topology visualization.

### Remote and Manual Fixes

R3P currently offers remote fixes for 17 settings: SMBv1, exposed RDP, USB AutoRun, PowerShell execution policy, UAC, Defender real-time protection, Windows Firewall, Defender Tamper Protection (best effort), Event Log, Guest account, LSASS protection, WDigest, RDP Network Level Authentication, AlwaysInstallElevated, the vulnerable-driver blocklist, HVCI, and one ASR rule. Administrators confirm a fix before it is queued. The confirmation highlights relevant risks, and the agent runs a fresh scan after execution; command completion alone is not treated as proof that protection is active.

### Preparing a Windows Endpoint for a Mock-Attack Demo

Run the collector on a disposable Windows 10/11 test VM with the endpoint protection product and policies you intend to demonstrate enabled. Run the collector elevated so permission failures are less likely to be mistaken for security blocking, and take a VM snapshot before making configuration changes. Do not turn off Defender or tamper protection, add exclusions, or weaken organizational policy just to force a mock test to pass or fail.

The VSS test performs a read-only inventory query, which Windows commonly permits; the mass-rename test only renames disposable files under the agent's temporary folder. A successful result means that exact benign action was allowed, not that ransomware encryption or VSS deletion would necessarily succeed. Default Windows Defender settings may allow these probes, and CFA/ASR rules do not necessarily target these exact actions. For a reliable presentation of individual settings/remediations, use simulated telemetry (`python demo_collector.py`) for the fleet view and a resettable Windows VM for actual configuration changes. Label simulated results clearly and do not present them as live endpoint enforcement evidence.

RDP disablement and Tamper Protection also include manual guidance: disabling RDP can cut off administration, and the Tamper Protection command is best effort, so verify it through Windows Security or the organization’s Defender/Intune policy. Other organization-dependent settings (such as backups, BitLocker recovery-key escrow, AppLocker, LAPS, and EDR behavior rules) show tailored guidance. The PowerShell execution-policy action is labeled as defense in depth: it is not a security boundary.

If agents are distributed as compiled executables, rebuild the agent from the updated `collector.py` and redeploy it to receive the in-app fix guide and current remediation behavior.

---

## Tech Stack

- **Agent:** Python 3.10+ (Win32 APIs, WMI, PowerShell subsystem, PyInstaller)
- **Backend:** FastAPI, SQLAlchemy, SQLite (WAL mode), Pydantic, WebSockets
- **Frontend:** React 18, Vite, Lucide-React, Chart.js
- **Analysis & Testing:** PyTest, Pandas, Matplotlib, Scipy, Tabulate

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

### 2. Docker Compose Deployment

```powershell
# Start frontend and backend in isolated containers
docker-compose up -d --build
```
* Dashboard: `http://localhost:5173` | API: `http://localhost:8000`

---

## Testing & Validation Suite

Run automated unit and integration tests (Scoring, Dynamic $Risk_{max}$, Heartbeat Monitor, Anomaly Detector):

```powershell
# Run the test suite (17 passed)
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

## Windows agent fix guide

Open **Fix guide** in the R3P Windows agent to browse remediation guidance, or choose **How to fix** next to a finding. Each guide explains why the check matters, safe manual steps, how to verify the result, and any important cautions. A guide is informational and never runs a command. Where an allowlisted local fix exists, **Apply fix** is a separate action and asks for confirmation first. It can require administrator rights, a restart, or coordination with centrally managed policy; review the guide and preserve a remote-management path before applying changes. Findings without an allowlisted fix must be handled through Windows or the organization's approved device-management process.

The active validation probes are limited simulations. The VSS probe performs a read-only WMI enumeration and does not delete shadow copies. The mass-rename probe creates disposable files under the agent's `%TEMP%` subfolder and renames those files; it does not encrypt user documents. An allowed probe is not proof that real ransomware would succeed, and a blocked probe is not proof of complete ransomware protection. In particular, a generic Defender setting or Controlled Folder Access is not guaranteed to block these exact probes. Review endpoint protection events and use vendor-supported validation in a disposable lab; do not disable WMI/backups, weaken protection, or add broad exclusions to force a desired result.

---
**License**: Academic / Open-Source Project
