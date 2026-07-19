"""
scoring.py — Risk scoring engine.

Maps the 18 security parameters (+ collector.py's fields) to a 0–100 risk
score and classifies each machine as SAFE / LOW RISK / HIGH RISK / CRITICAL.

Kill-chain phase weights:
  Entry Vector          30 pts  (4 params)
  Execution             25 pts  (4 params)
  Evasion/Persistence   20 pts  (4 params)
  Lateral Movement      15 pts  (3 params)
  Recovery Prevention   10 pts  (3 params)
"""

from schemas import CollectorData

PHASES = {
    "Entry Vector": ["smb_v1_enabled", "rdp_enabled", "autorun_enabled", "open_network_shares"],
    "Execution": ["macro_execution_enabled", "powershell_unrestricted", "uac_disabled", "applocker_absent"],
    "Evasion & Persistence": ["defender_disabled", "firewall_disabled", "tamper_protection_off", "event_logging_disabled"],
    "Lateral Movement": ["admin_shares_enabled", "lsass_protection_off", "guest_account_active"],
    "Recovery Prevention": ["vss_deleted", "backup_absent", "bitlocker_off"]
}

# ── Parameter weights (name → contribution to risk score 0-100) ─────────────
PARAM_WEIGHTS: dict[str, float] = {
    # Entry Vector (total 30)
    "smb_v1_enabled":          10.0,
    "rdp_enabled":              8.0,   # mapped from rdp_open
    "autorun_enabled":          6.0,
    "open_network_shares":      6.0,

    # Execution (total 25)
    "macro_execution_enabled":  7.0,
    "powershell_unrestricted":  7.0,
    "uac_disabled":             6.0,
    "applocker_absent":         5.0,

    # Evasion/Persistence (total 20)
    "defender_disabled":        7.0,
    "firewall_disabled":        5.0,   # mapped from firewall_on == False
    "tamper_protection_off":    4.0,
    "event_logging_disabled":   4.0,

    # Lateral Movement (total 15)
    "admin_shares_enabled":     6.0,
    "lsass_protection_off":     5.0,
    "guest_account_active":     4.0,

    # Recovery Prevention (total 10)
    "vss_deleted":              4.0,
    "backup_absent":            4.0,   # mapped from backup_configured == False
    "bitlocker_off":            2.0,
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
    total  = 0.0
    flagged: dict[str, list[str]] = {phase: [] for phase in PHASES}

    for param, is_risky in params.items():
        if is_risky:
            total += PARAM_WEIGHTS.get(param, 0.0)
            for phase, p_list in PHASES.items():
                if param in p_list:
                    flagged[phase].append(param)
                    break
    
    # Remove empty phases
    flagged = {k: v for k, v in flagged.items() if v}

    total = min(total, 100.0)

    if total < 20:
        risk_class = "SAFE"
    elif total < 50:
        risk_class = "LOW RISK"
    elif total < 80:
        risk_class = "HIGH RISK"
    else:
        risk_class = "CRITICAL"

    return round(total, 2), risk_class, flagged
