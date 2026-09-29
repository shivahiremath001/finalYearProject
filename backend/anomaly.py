"""
anomaly.py — Rolling Z-Score Anomaly Detection Engine.

Detects sudden behavioral changes in a machine's risk score by computing
a rolling z-score over the last N scans.

Algorithm:
    z = (x - μ) / σ

    Where:
      x = current scan's risk score
      μ = rolling mean of the last N scores
      σ = rolling standard deviation of the last N scores

    If |z| > THRESHOLD (default 2.0), the scan is flagged as an anomaly.

    - z > 2.0  → "spike"  (risk score jumped unusually high — security degradation)
    - z < -2.0 → "drop"   (risk score dropped unusually fast — remediation or tampering)

Edge cases:
    - Fewer than MIN_HISTORY (3) scans → no anomaly detection (insufficient data)
    - σ = 0 (all scores identical) → addressed by std floor (sigma_eff = max(sigma, 1.0))
    - If a remediation command was successfully executed in the last 5 minutes and the score dropped, the anomaly is labeled as expected ("remediation_applied").
"""

import math
from dataclasses import dataclass
from sqlalchemy.orm import Session
from sqlalchemy import desc

# ── Configuration ─────────────────────────────────────────────────────────────
WINDOW_SIZE = 10  # Number of historical scans to consider
MIN_HISTORY = 3  # Minimum scans before anomaly detection activates
Z_THRESHOLD = 2.0  # |z| must exceed this to flag an anomaly


@dataclass
class AnomalyResult:
    """Result of anomaly detection for a single scan."""

    is_anomaly: bool
    z_score: float | None
    rolling_mean: float | None
    rolling_std: float | None
    direction: str  # "spike" | "drop" | "normal"
    scans_analyzed: int


def detect_anomaly(
    db: Session,
    hostname: str,
    current_score: float,
) -> AnomalyResult:
    """
    Compute rolling z-score for a machine's latest risk score.

    Args:
        db: SQLAlchemy session
        hostname: Machine hostname
        current_score: The risk score from the current (just-completed) scan

    Returns:
        AnomalyResult with z-score, rolling stats, and anomaly flag
    """
    from models import ConfigurationScan, RemediationCommand
    from datetime import datetime, timezone, timedelta

    # Query the last N risk scores for this machine (excluding the current scan
    # which hasn't been inserted yet)
    recent_scans = (
        db.query(ConfigurationScan.risk_score)
        .filter_by(hostname=hostname)
        .order_by(desc(ConfigurationScan.scanned_at))
        .limit(WINDOW_SIZE)
        .all()
    )

    historical_scores = [row.risk_score for row in recent_scans]
    n = len(historical_scores)

    # Not enough history — can't do anomaly detection
    if n < MIN_HISTORY:
        return AnomalyResult(
            is_anomaly=False,
            z_score=None,
            rolling_mean=None,
            rolling_std=None,
            direction="normal",
            scans_analyzed=n,
        )

    # Compute rolling mean and standard deviation
    # Using Bessel's correction (n-1) for unbiased sample standard deviation
    mean = sum(historical_scores) / n
    variance = sum((s - mean) ** 2 for s in historical_scores) / (n - 1)
    std = math.sqrt(variance)

    # Use a standard deviation floor (sigma_eff = max(std, 1.0)).
    # This prevents zero-variance histories from throwing +/- inf or 999 z-scores
    # on minor 0.1 score fluctuations. A score must change by at least 1.0
    # multiplied by the Z_THRESHOLD to be considered anomalous.
    sigma_eff = max(std, 1.0)

    # Compute z-score using effective sigma
    z = (current_score - mean) / sigma_eff

    # Determine direction and anomaly flag
    is_anomaly = abs(z) > Z_THRESHOLD
    if z > Z_THRESHOLD:
        direction = "spike"
    elif z < -Z_THRESHOLD:
        direction = "drop"
    else:
        direction = "normal"

    # If the score dropped (anomaly or not), check if a remediation command
    # was completed successfully ("done") within the last 5 minutes.
    if direction == "drop" and is_anomaly:
        recent_cmd = (
            db.query(RemediationCommand)
            .filter(RemediationCommand.hostname == hostname)
            .filter(RemediationCommand.status == "done")
            .filter(RemediationCommand.completed_at != None)
            .order_by(desc(RemediationCommand.completed_at))
            .first()
        )
        if recent_cmd:
            completed_ts = recent_cmd.completed_at.replace(tzinfo=timezone.utc).timestamp() if recent_cmd.completed_at.tzinfo is None else recent_cmd.completed_at.timestamp()
            now_ts = datetime.now(timezone.utc).timestamp()
            if now_ts - completed_ts <= 300:  # 5 minutes
                is_anomaly = False
                direction = "remediation_applied"

    return AnomalyResult(
        is_anomaly=is_anomaly,
        z_score=round(z, 4),
        rolling_mean=round(mean, 2),
        rolling_std=round(std, 2),
        direction=direction,
        scans_analyzed=n,
    )
