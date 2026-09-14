# R3P Project Changelog

This document tracks all modifications, enhancements, and bug fixes applied to the Ransomware Readiness & Risk Profiler (R3P) codebase.

## [2026-09-14] - Docker Containerization & UI Polish

### 🐳 Infrastructure & DevOps (Docker)
- **Containerization:** Fully containerized the R3P Admin platform using Docker. Created isolated environments for the FastAPI backend (`python:3.10-slim`) and React frontend (`node:20-slim`).
- **Orchestration:** Implemented `docker-compose.yml` to orchestrate services, map local volumes for live-reloading, and safely persist the SQLite database to the host machine.
- **Build Optimization:** Added `.dockerignore` files to both frontend and backend to prevent local environment caches (`node_modules`, `venv`) from polluting the Docker images. Fixed Node native-bindings conflict in the Vite build process.

### 🖥️ Frontend & UI Polish
- **Policies Dashboard Overhaul:** Refactored `PoliciesView.jsx` to render all 27 vulnerability parameters. Grouped the parameters cleanly by their respective kill-chain phases within the HTML `optgroup` elements.
- **Aesthetic Refinements:** Added custom CSS (`App.css`) to fix native dropdown styling, ensuring visibility of `optgroup` headers, applying a custom chevron icon, and maintaining a cohesive premium dark-mode aesthetic.

### 🐛 Bug Fixes & Testing
- **Automated Unit Testing:** Implemented `pytest` for the `scoring.py` risk engine. Tests verify baseline safe scores, critical vulnerability overrides, and asset criticality multiplier logic.
- **Risk Engine Math Bug:** The new unit tests caught a mathematical flaw where the `asset_criticality` multiplier was accidentally applied to both the numerator and denominator, canceling itself out. Fixed the normalization formula in `scoring.py` so Domain Controllers correctly yield higher severity scores.
- **Agent Mock Attack Detection:** Fixed a logic flaw in `collector.py` where the VSS Enumeration mock attack was swallowing PowerShell errors. The agent now properly detects if an EDR blocks the mock attack, ensuring accurate telemetry reporting.

## [2026-09-13] - Phase 1 (Risk Scoring Refactor) & Phase 2 (BYOVD/EDR-Killer Defenses)

### 📈 Phase 1: Risk Engine & Posture Drift
- **Risk Formula Overhaul:** Updated `scoring.py` to calculate risk using the formula: `Risk = Severity × Likelihood × AssetCriticality`. Replaced static arbitrary weights with literature-backed severity and likelihood scores.
- **Asset Criticality Context:** Added `asset_criticality` mapping to differentiate between Domain Controllers (weight 2.0), Servers (1.5), and standard Workstations (1.0). Added `asset_type` to telemetry payload.
- **Explainable Posture Drift:** Modified `main.py` ingestion pipeline to compute `posture_diff` by comparing current configurations against the most recent scan. Rebranded "Anomaly Detection" to "Posture Drift" on the dashboard, now displaying exact string diffs of what changed (e.g., `+ wdigest_enabled`, `- smb_v1_enabled`).

### 🛡️ Phase 2: BYOVD & Advanced EDR-Killer Protections
- **Vulnerable Driver Blocklist:** Added `vulnerable_driver_blocklist_enabled` check (BYOVD defense).
- **HVCI Memory Integrity:** Added `hvci_enabled` check to verify kernel code integrity.
- **ASR Rules:** Added `asr_rules_configured` check to verify basic Attack Surface Reduction.
- **Remediation Logic:** Added PowerShell fix commands in `remediation_registry.py` for BYOVD blocklist, HVCI, and ASR rule enablement.
- **Agent Updates:** Updated `collector.py` and `demo_collector.py` to harvest and simulate these advanced telemetry checks.
- **Frontend Integration:** Added the new checks to `App.jsx` MITRE mappings and to the `PoliciesView.jsx` exceptions dropdown.

## [2026-09-13] - Architecture & Check Enhancements

### ⚡ Performance
- **Multithreading in Collector:** Refactored `run_all_checks` in both `collector.py` and `demo_collector.py` to utilize `concurrent.futures.ThreadPoolExecutor`. This allows the agent to run configuration checks concurrently, drastically reducing the overall scan execution time.

### 🛡️ New MITRE ATT&CK Checks Added
Expanded the agent's scanning capabilities to cover 4 new critical ransomware vectors:
1. **WDigest Credentials Enabled (`wdigest_enabled`)** - Mapped to *T1003.001 (Credential Access)*. Checks if Windows stores passwords in clear text in LSASS memory.
2. **LAPS Absent (`laps_absent`)** - Mapped to *T1562 (Defense Evasion)*. Verifies if Microsoft Local Administrator Password Solution is installed.
3. **NLA Disabled for RDP (`nla_disabled`)** - Mapped to *T1021.001 (Lateral Movement)*. Checks if Network Level Authentication is bypassed for Remote Desktop.
4. **AlwaysInstallElevated Policy Active (`always_install_elevated`)** - Mapped to *T1548.002 (Privilege Escalation)*. Checks if standard users are permitted to install MSI packages as SYSTEM.

### 🗄️ Backend & Database
- **Schema Updates:** Added the 4 new check fields to `schemas.py` (Pydantic validation) and `models.py` (SQLAlchemy ORM).
- **Database Migration:** Executed live `ALTER TABLE` SQL commands on the `r3p.db` SQLite database to inject the new columns without destroying existing telemetry data.
- **Scoring Engine:** Updated `scoring.py` with severity weights, descriptions, and kill-chain phase mappings for the new checks.
- **Remediation Registry:** Added PowerShell fix commands and rollback instructions for the 4 new checks in `remediation_registry.py`.

### 🖥️ Frontend (React/Vite)
- **UI Mappings:** Updated `App.jsx` constants (`PARAM_LABELS`, `PARAM_SEVERITY`, `PARAM_DESCRIPTIONS`, `MITRE_MAPPING`) to ensure the new checks render beautifully on the dashboard with correct MITRE ID badges.
- **Policy Exceptions:** Updated `PoliciesView.jsx` dropdowns to allow administrators to safelist/ignore the 4 new parameters.

### 🐛 Bug Fixes & Stability
- **JWT Session Invalidation:** Fixed an issue in `backend/auth.py` where the development `uvicorn` server generated a random `JWT_SECRET` on every hot-reload. Replaced it with a static development secret so admin dashboard sessions survive backend restarts.
- **Dummy Machine Seeding:** Implemented and executed a `seed_dummy_machine` function in `crud.py` to inject `DUMMY-DEMO-01` into the database, complete with a full scan profile for demonstration and testing purposes.
