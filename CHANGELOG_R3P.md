# R3P Project Changelog

## T1: Deterministic Scoring Engine & Dynamic Risk_max
- **What**: Implemented dynamic `RISK_MAX` computation at import time from the sum of S*L. Added startup validation to ensure all schema fields are mapped in severity and likelihood dictionaries. Added `explain_score()` function to return top contributors.
- **Why**: Eliminates hardcoded magic numbers (75) and ensures the scoring system remains internally consistent if new parameters are added. `explain_score()` provides immediate visibility into why a host is failing.
- **Files Touched**: `backend/scoring.py`, `backend/schemas.py`, `backend/main.py`, `backend/tests/test_scoring.py`
- **How to demo**: Start the backend; check the startup logs for successful validation. Ingest a telemetry payload and see the `top_contributors` field in the JSON response indicating exactly which parameters contributed most to the risk score.

## T2: Heartbeat and Offline Detection
- **What**: Added a background monitor in the FastAPI `lifespan` that checks every 30 seconds for machines with no recent ingest (150s cutoff). Broadcasts WebSocket events `host_offline` and `host_online` when a machine's status changes. Updated `MachineRegistry` to track `status`.
- **Why**: Silent hosts were never flagged before. Now, if an agent is killed, disconnected, or tampered with, the dashboard is immediately notified, preventing blind spots.
- **Files Touched**: `backend/models.py`, `backend/schemas.py`, `backend/crud.py`, `backend/main.py`, `backend/tests/test_heartbeat.py`
- **How to demo**: Run the backend and an agent. Kill the agent. Within ~30 seconds, a `host_offline` WebSocket event will fire, and the API `/machines` will show the machine as OFFLINE. Restart the agent to see `host_online`.

## T3: Fix the Anomaly Detector
- **What**: Replaced the +/-999 sentinel in `anomaly.py` with an effective standard deviation floor (`sigma_eff = max(sigma, 1.0)`). Added logic to suppress "drop" anomalies (flag as `remediation_applied`) if a remediation command was successfully executed in the last 5 minutes.
- **Why**: The zero-variance sentinel caused massive false positives (+/- 999 z-score) for minor 0.1 score fluctuations. The new sigma floor requires statistically meaningful changes. Furthermore, expected score drops following a remediation no longer trigger false "drop" alerts.
- **Files Touched**: `backend/anomaly.py`, `backend/tests/test_anomaly.py`
- **How to demo**: Ingest 5 identical clean scans (z=0). Then ingest a scan with a minor change (e.g. 0.1 score diff) - it will no longer trigger an anomaly. Execute a remediation command, wait for it to finish, and observe the subsequent score drop is labeled `remediation_applied` instead of `drop` anomaly.

## T4: Weight Sensitivity Analysis
- **What**: Built a synthetic analysis script (`analysis/sensitivity.py`) that generates 300 random hosts and scores them, then repeatedly perturbs all Severity and Likelihood weights by up to 20% to measure ranking stability.
- **Why**: Proves that the scoring model's prioritization is mathematically robust and not overly brittle to minor, subjective adjustments in the assigned weights. Also suppresses false-positive static analysis (Pyrefly) warnings caused by cross-directory imports.
- **Files Touched**: `analysis/sensitivity.py`, `analysis/output/sensitivity.*`
- **How to demo**: Open `analysis/output/sensitivity.png` or `sensitivity.md` to see the high Spearman correlation (>0.95), proving the rankings hold steady.

## T5: Synthetic Validation with Named Scenarios
- **What**: Created `analysis/validate.py` to define 5 explicit edge-case host profiles (e.g. hardened server, lockbit-style exposed RDP, phishing macro chain). Scored them and proved expected ordering (hardened < typical < lockbit). Generates a histogram for 500 random hosts.
- **Why**: Synthetically validates that the scoring engine behaves correctly across known ransomware attack archetypes, proving real-world applicability for the viva.
- **Files Touched**: `analysis/validate.py`, `analysis/output/validate_*`
- **How to demo**: Review `validate_scenarios_SYNTHETIC.csv` to see how the profiles score, and confirm the LockBit profile consistently ranks as CRITICAL while the hardened profile scores SAFE.
