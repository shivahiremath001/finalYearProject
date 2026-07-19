"""
scoring.py — Risk scoring engine.

Maps the 18 security parameters (+ collector.py's fields) to a severity-weighted 
risk score (0–100) and classifies each machine as SAFE / LOW RISK / HIGH RISK / CRITICAL.

Weighting Rationale:
Each check is assigned a severity weight from 1 to 5:
  Weight 5 (Critical): e.g., LSASS disabled, backups/VSS deleted, SMBv1 enabled.
  Weight 1-4 (Lower impact): e.g., AutoRun enabled, Guest account active.
The final score is normalized to 100. If any single check with weight 5 fails, 
the result is escalated to at least "HIGH RISK" regardless of the total score.
"""

from schemas import CollectorData

PHASES = {
    "Entry Vector": ["smb_v1_enabled", "rdp_enabled", "autorun_enabled", "open_network_shares"],
    "Execution": ["macro_execution_enabled", "powershell_unrestricted", "uac_disabled", "applocker_absent"],
    "Evasion & Persistence": ["defender_disabled", "firewall_disabled", "tamper_protection_off", "event_logging_disabled"],
    "Lateral Movement": ["admin_shares_enabled", "lsass_protection_off", "guest_account_active"],
    "Recovery Prevention": ["vss_deleted", "backup_absent", "bitlocker_off"]
}

# ── Parameter weights (name → severity weight 1-5) ─────────────
PARAM_WEIGHTS: dict[str, float] = {
    # Entry Vector
    "smb_v1_enabled":           5.0,  # Critical
    "rdp_enabled":              4.0,  # High
    "autorun_enabled":          2.0,  # Low
    "open_network_shares":      3.0,  # Medium

    # Execution
    "macro_execution_enabled":  4.0,
    "powershell_unrestricted":  4.0,
    "uac_disabled":             3.0,
    "applocker_absent":         2.0,

    # Evasion/Persistence
    "defender_disabled":        4.0,
    "firewall_disabled":        4.0,
    "tamper_protection_off":    3.0,
    "event_logging_disabled":   2.0,

    # Lateral Movement
    "admin_shares_enabled":     3.0,
    "lsass_protection_off":     5.0,  # Critical
    "guest_account_active":     2.0,

    # Recovery Prevention
    "vss_deleted":              5.0,  # Critical
    "backup_absent":            5.0,  # Critical
    "bitlocker_off":            5.0,  # Critical
}


def _translate(data: CollectorData) -> dict[str, bool]:
    """
    Convert collector.py field names → internal parameter names.
    collector sends:  rdp_open, firewall_on, backup_configured
    models use:       rdp_enabled, firewall_disabled, backup_absent
    """
    return {
        # Entry Vector
        "smb_v1_enabled":         data.smb_v1_enabled,
        "rdp_enabled":            data.rdp_open,               # collector field
        "autorun_enabled":        data.autorun_enabled,
        "open_network_shares":    data.open_network_shares,

        # Execution
        "macro_execution_enabled": data.macro_execution_enabled,
        "powershell_unrestricted": data.powershell_unrestricted,
        "uac_disabled":            data.uac_disabled,
        "applocker_absent":        data.applocker_absent,

        # Evasion/Persistence
        "defender_disabled":       data.defender_disabled,
        "firewall_disabled":       not data.firewall_on,        # invert firewall_on
        "tamper_protection_off":   data.tamper_protection_off,
        "event_logging_disabled":  data.event_logging_disabled,

        # Lateral Movement
        "admin_shares_enabled":    data.admin_shares_enabled,
        "lsass_protection_off":    data.lsass_protection_off,
        "guest_account_active":    data.guest_account_active,

        # Recovery Prevention
        "vss_deleted":             data.vss_deleted,
        "backup_absent":           not data.backup_configured,  # invert backup_configured
        "bitlocker_off":           data.bitlocker_off,
    }


def score(data: CollectorData) -> tuple[float, str, list[str]]:
    """
    Returns:
        risk_score  (0.0 – 100.0)
        risk_class  ("SAFE" | "LOW RISK" | "HIGH RISK" | "CRITICAL")
        flagged     dict mapping phase name to list of flagged parameter names
    """
    params = _translate(data)
    total_weight = 0.0
    max_weight = sum(PARAM_WEIGHTS.values())
    has_critical_failure = False
    flagged: dict[str, list[str]] = {phase: [] for phase in PHASES}

    for param, is_risky in params.items():
        if is_risky:
            weight = PARAM_WEIGHTS.get(param, 0.0)
            total_weight += weight
            if weight == 5.0:
                has_critical_failure = True
            for phase, p_list in PHASES.items():
                if param in p_list:
                    flagged[phase].append(param)
                    break
    
    # Remove empty phases
    flagged = {k: v for k, v in flagged.items() if v}

    # Normalize to 0-100 scale
    total = (total_weight / max_weight) * 100.0 if max_weight > 0 else 0.0
    total = min(total, 100.0)

    if total < 20:
        risk_class = "SAFE"
    elif total < 50:
        risk_class = "LOW RISK"
    elif total < 80:
        risk_class = "HIGH RISK"
    else:
        risk_class = "CRITICAL"

    # Escalation rule for weight 5
    if has_critical_failure and risk_class in ["SAFE", "LOW RISK"]:
        risk_class = "HIGH RISK"

    return round(total, 2), risk_class, flagged
