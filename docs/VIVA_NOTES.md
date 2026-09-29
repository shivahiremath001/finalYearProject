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
