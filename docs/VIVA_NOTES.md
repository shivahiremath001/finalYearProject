# Viva Defense Notes

## T1: Deterministic Scoring Engine
**What to say:** "I redesigned the scoring engine to calculate the maximum possible risk dynamically at import time, rather than relying on a hardcoded ceiling. This ensures the model scales automatically if we add new telemetry parameters, and the new `explain_score` function provides full transparency into exactly which misconfigurations are driving the risk score."
**Limitation:** The weighting model still inherently treats all parameters as additive and independent, which doesn't perfectly capture chained vulnerabilities where the combined risk is greater than the sum of its parts.

## T2: Heartbeat and Offline Detection
**What to say:** "To prevent agents from failing silently, I implemented a background heartbeat monitor using asyncio that runs independently of the main API request loop. If an endpoint stops sending telemetry for more than two and a half minutes, the backend automatically flags it as offline and pushes a real-time WebSocket alert to the dashboard."
**Limitation:** If the backend server reboots, it relies on the first scheduled background sweep to re-evaluate host statuses, and the in-memory state of the WebSocket manager is lost until clients reconnect.

## T3: Fix the Anomaly Detector
**What to say:** "I hardened the rolling Z-score anomaly detector by implementing a standard deviation floor, which eliminates the false-positive infinity spikes we saw when a perfectly static machine experienced a minor score change. Furthermore, the engine is now remediation-aware, so it suppresses 'drop' anomaly alerts if the score improvement immediately follows a successfully executed remediation command."
**Limitation:** The anomaly detector relies on a simplistic rolling window of the last 10 scans, meaning it only captures short-term behavioral drift and lacks seasonal or long-term baseline awareness.

## T4: Weight Sensitivity Analysis
**What to say:** "To prove the mathematical robustness of the model, I built a synthetic Monte Carlo analysis script that perturbs all assigned severity and likelihood weights by up to 20% across a thousand iterations. The results demonstrated a Spearman rank correlation of over 0.95, confirming that the system's ability to prioritize the most critical hosts is highly resilient to minor imperfections in weight assignment."
**Limitation:** The synthetic hosts used in this analysis were generated using an independent random distribution for each telemetry flag, which may not perfectly reflect the correlated misconfigurations found in real-world networks (e.g., a host with Defender disabled is also highly likely to have Firewall disabled).

## T5: Synthetic Validation with Named Scenarios
**What to say:** "I validated the scoring logic against well-known ransomware profiles, such as a 'LockBit-style' exposed RDP entry vector and a 'phishing macro chain' execution vector. The engine successfully and deterministically prioritized the highly vulnerable profiles as CRITICAL, while correctly scoring hardened profiles as SAFE."
**Limitation:** While these named scenarios cover common textbook attack chains, the validation is entirely synthetic and has not been back-tested against a live dataset of compromised enterprise machines.

## T6: Deception Technology — Honeytoken Canary Subsystem
**What to say:** "All 27 telemetry parameters are passive configuration checks — they detect misconfigurations before an attack. The honeytoken subsystem adds an active deception layer. A hidden bait file (`!0000_financial_records.docx`) is deployed to `C:\Users\Public\Documents` using Win32 `SetFileAttributesW` to make it invisible to standard Explorer browsing. A background daemon thread polls its modification timestamp every 2 seconds. If ransomware renames it — the signature file manipulation behavior of encryption — `HONEYPOT_TRIPPED` is set globally. The next ingest bypasses the entire weighted scoring engine and immediately reports 100/100 CRITICAL with a dedicated `Active Attack` kill-chain phase, distinct from all configuration findings."

**Why Honeytoken and not just mock attacks?:** "The mock attack probes (T1486, T1490) test whether defenses *block* simulated attacks. The honeytoken detects a *real* attacker already present on the machine and actively encrypting files — defenses may have already been defeated. These are two distinct and complementary detection layers."

**Self-healing design:** "If a user accidentally deletes the bait file, the monitor silently recreates it. Only a *rename* event (ransomware extension swap) triggers the alert — eliminating false positives from ordinary file system operations."

**Limitation:** The honeytoken monitors only its own specific bait file and directory. A sophisticated attacker aware of the canary location could theoretically avoid it. In production, multiple honeytokens distributed across multiple locations would be deployed. Additionally, the flag persists only in memory until the next restart of the agent; a system reboot after a honeypot trip clears the flag (though the renamed file would still be visible on disk as evidence).

---

## Deployment Architecture Q&A

**Q: How is the agent distributed to target machines without Python installed?**
> "Using PyInstaller, the `collector.py` script is compiled into a fully self-contained Windows executable (`R3P_Agent.exe`) via `build_collector.bat`. This bundles the Python runtime, all dependencies (requests, pystray, Pillow, tkinter), and the agent code into a single portable binary — no installation required on the target machine."

**Q: How does the agent know which server to connect to?**
> "On first launch, the agent shows a setup dialog prompting for the server IP or Ngrok URL. This is saved to `r3p_server.txt` in the same directory as the executable. On subsequent launches, the file is read automatically. Deleting `r3p_server.txt` resets the configuration. For bulk deployment, `r3p_server.txt` can be pre-populated and shipped alongside the executable."

**Q: How does it work across the public internet, not just LAN?**
> "The backend is exposed via an Ngrok persistent tunnel (`run_project.bat`). Ngrok provides a stable public HTTPS URL (`sleep-abnormal-sputter.ngrok-free.dev`) that proxies to the local FastAPI server on port 8000. All agent telemetry, command polling, and acknowledgments travel over this encrypted HTTPS tunnel — no static IP or open firewall port required on the server side."

**Q: Why does the agent use `r3p_server.txt` instead of a hardcoded IP?**
> "Hardcoding the server IP would require recompiling the executable every time the server changes location. The text file approach allows the same binary to be redeployed to a different server by simply replacing the config file, without any recompilation."

---

## Key Technical Terms for Presentations

| Component | Technical Term |
|---|---|
| `R3P_Agent.exe` | **Host-Based Endpoint Telemetry Sensor & Autonomous Monitoring Daemon** |
| Honeytoken system | **Deception Technology & Filesystem Canary Trap Subsystem** |
| `r3p_server.txt` | **Persistent Agent Configuration Store / Endpoint Registration Token** |
| Remediation engine | **Allowlisted Remediation Actuator & Policy Enforcement Engine** |
| Backend API | **Centralized Telemetry Ingestion & Orchestration Server** |
| Risk scoring | **Multi-Factor Posture Assessment & Weighted Risk Matrix (MCDA)** |
| Frontend dashboard | **SOC Command & Visibility Console (Single-Pane-of-Glass)** |
| Ngrok tunnel | **Encrypted Zero-Trust Ingress Transport Layer** |
| `build_collector.bat` | **PyInstaller Compilation Pipeline & Distribution Script** |
| `setup_agent.bat` | **Persistent Agent Registration & Scheduled Task Deployment Script** |

