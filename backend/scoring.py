"""
scoring.py — Risk scoring engine with MITRE ATT&CK mapping.

Maps the 18 security parameters (+ collector.py's fields) to a severity-weighted 
risk score (0–100) and classifies each machine as SAFE / LOW RISK / HIGH RISK / CRITICAL.

Each parameter is mapped to a MITRE ATT&CK technique ID for industry-standard context.

Weighting Rationale:
Each check is assigned a severity weight from 1 to 5:
  Weight 5 (Critical): e.g., LSASS disabled, backups/VSS deleted, SMBv1 enabled.
  Weight 1-4 (Lower impact): e.g., AutoRun enabled, Guest account active.
The final score is normalized to 100. If any single check with weight 5 fails, 
the result is escalated to at least "HIGH RISK" regardless of the total score.
"""

from schemas import CollectorData

PHASES = {
    "Entry Vector": ["smb_v1_enabled", "rdp_enabled", "autorun_enabled", "open_network_shares", "nla_disabled"],
    "Execution": ["macro_execution_enabled", "powershell_unrestricted", "uac_disabled", "applocker_absent", "always_install_elevated"],
    "Evasion & Persistence": ["defender_disabled", "firewall_disabled", "tamper_protection_off", "event_logging_disabled", "vulnerable_driver_blocklist_enabled", "hvci_enabled", "asr_rules_configured"],
    "Lateral Movement": ["admin_shares_enabled", "lsass_protection_off", "guest_account_active", "wdigest_enabled", "laps_absent"],
    "Recovery Prevention": ["vss_deleted", "backup_absent", "bitlocker_off"],
    "Active Validation (Mock Attacks)": ["mock_attack_vss_enum_succeeded", "mock_attack_mass_rename_succeeded"]
}

# ── Severity weights (name → severity weight 1-5) ─────────────
SEVERITY_WEIGHTS: dict[str, float] = {
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

    # New Fields
    "nla_disabled":             4.0,  # High
    "always_install_elevated":  5.0,  # Critical
    "wdigest_enabled":          5.0,  # Critical
    "laps_absent":              3.0,  # Medium
    "vulnerable_driver_blocklist_enabled": 5.0,  # Critical (if not enabled)
    "hvci_enabled":             4.0,  # High (if not enabled)
    "asr_rules_configured":     4.0,  # High (if not configured)

    # Phase 3 Active Validation
    "mock_attack_vss_enum_succeeded": 5.0,     # Critical (if not blocked)
    "mock_attack_mass_rename_succeeded": 5.0,  # Critical (if not blocked)
}

# ── Likelihood weights (name → likelihood 0.1-1.0 based on real-world frequency) ─────────────
LIKELIHOOD_WEIGHTS: dict[str, float] = {
    # Entry Vector
    "smb_v1_enabled":           0.4,  # Lower likelihood today
    "rdp_enabled":              0.9,  # Very high (dominant initial access)
    "autorun_enabled":          0.3,
    "open_network_shares":      0.7,

    # Execution
    "macro_execution_enabled":  0.8,
    "powershell_unrestricted":  1.0,  # Ubiquitous in ransomware execution
    "uac_disabled":             0.6,
    "applocker_absent":         0.5,

    # Evasion/Persistence
    "defender_disabled":        0.9,
    "firewall_disabled":        0.6,
    "tamper_protection_off":    0.8,
    "event_logging_disabled":   0.7,

    # Lateral Movement
    "admin_shares_enabled":     0.8,
    "lsass_protection_off":     0.9,  # Mimikatz is extremely common
    "guest_account_active":     0.4,

    # Recovery Prevention
    "vss_deleted":              1.0,  # Literally every ransomware does this
    "backup_absent":            0.8,
    "bitlocker_off":            0.5,

    # New Fields
    "nla_disabled":             0.8,
    "always_install_elevated":  0.6,
    "wdigest_enabled":          0.7,
    "laps_absent":              0.8,
    "vulnerable_driver_blocklist_enabled": 0.9,  # Very high (BYOVD is dominant)
    "hvci_enabled":             0.8,
    "asr_rules_configured":     0.8,

    # Phase 3 Active Validation
    "mock_attack_vss_enum_succeeded": 1.0,     # If it succeeded, defense absolutely failed
    "mock_attack_mass_rename_succeeded": 1.0,  # If it succeeded, defense absolutely failed
}

# ── MITRE ATT&CK Mapping ──────────────────────────────────────────────────────
# Reference: MITRE ATT&CK® Framework v15 — https://attack.mitre.org/
MITRE_MAPPING: dict[str, dict[str, str]] = {
    # Entry Vector
    "smb_v1_enabled": {
        "technique_id":   "T1210",
        "technique_name": "Exploitation of Remote Services",
        "tactic":         "Initial Access",
    },
    "rdp_enabled": {
        "technique_id":   "T1021.001",
        "technique_name": "Remote Desktop Protocol",
        "tactic":         "Lateral Movement",
    },
    "autorun_enabled": {
        "technique_id":   "T1091",
        "technique_name": "Replication Through Removable Media",
        "tactic":         "Initial Access",
    },
    "open_network_shares": {
        "technique_id":   "T1021.002",
        "technique_name": "SMB/Windows Admin Shares",
        "tactic":         "Lateral Movement",
    },

    # Execution
    "macro_execution_enabled": {
        "technique_id":   "T1204.002",
        "technique_name": "Malicious File",
        "tactic":         "Execution",
    },
    "powershell_unrestricted": {
        "technique_id":   "T1059.001",
        "technique_name": "PowerShell",
        "tactic":         "Execution",
    },
    "uac_disabled": {
        "technique_id":   "T1548.002",
        "technique_name": "Bypass User Account Control",
        "tactic":         "Privilege Escalation",
    },
    "applocker_absent": {
        "technique_id":   "T1204",
        "technique_name": "User Execution",
        "tactic":         "Execution",
    },

    # Evasion & Persistence
    "defender_disabled": {
        "technique_id":   "T1562.001",
        "technique_name": "Disable or Modify Tools",
        "tactic":         "Defense Evasion",
    },
    "firewall_disabled": {
        "technique_id":   "T1562.004",
        "technique_name": "Disable or Modify System Firewall",
        "tactic":         "Defense Evasion",
    },
    "tamper_protection_off": {
        "technique_id":   "T1562.001",
        "technique_name": "Disable or Modify Tools",
        "tactic":         "Defense Evasion",
    },
    "event_logging_disabled": {
        "technique_id":   "T1562.002",
        "technique_name": "Disable Windows Event Logging",
        "tactic":         "Defense Evasion",
    },

    # Lateral Movement
    "admin_shares_enabled": {
        "technique_id":   "T1021.002",
        "technique_name": "SMB/Windows Admin Shares",
        "tactic":         "Lateral Movement",
    },
    "lsass_protection_off": {
        "technique_id":   "T1003.001",
        "technique_name": "LSASS Memory",
        "tactic":         "Credential Access",
    },
    "guest_account_active": {
        "technique_id":   "T1078.001",
        "technique_name": "Default Accounts",
        "tactic":         "Persistence",
    },

    # Recovery Prevention
    "vss_deleted": {
        "technique_id":   "T1490",
        "technique_name": "Inhibit System Recovery",
        "tactic":         "Impact",
    },
    "backup_absent": {
        "technique_id":   "T1490",
        "technique_name": "Inhibit System Recovery",
        "tactic":         "Impact",
    },
    "bitlocker_off": {
        "technique_id":   "T1486",
        "technique_name": "Data Encrypted for Impact",
        "tactic":         "Impact",
    },
    
    # New Fields
    "nla_disabled": {
        "technique_id":   "T1021.001",
        "technique_name": "Remote Desktop Protocol",
        "tactic":         "Lateral Movement",
    },
    "always_install_elevated": {
        "technique_id":   "T1548.002",
        "technique_name": "Bypass User Account Control",
        "tactic":         "Privilege Escalation",
    },
    "wdigest_enabled": {
        "technique_id":   "T1003.001",
        "technique_name": "LSASS Memory (WDigest)",
        "tactic":         "Credential Access",
    },
    "laps_absent": {
        "technique_id":   "T1562",
        "technique_name": "Impair Defenses",
        "tactic":         "Defense Evasion",
    },
    "vulnerable_driver_blocklist_enabled": {
        "technique_id":   "T1068",
        "technique_name": "Exploitation for Privilege Escalation (BYOVD)",
        "tactic":         "Privilege Escalation",
    },
    "hvci_enabled": {
        "technique_id":   "T1562.001",
        "technique_name": "Disable or Modify Tools",
        "tactic":         "Defense Evasion",
    },
    "asr_rules_configured": {
        "technique_id":   "T1562.001",
        "technique_name": "Disable or Modify Tools",
        "tactic":         "Defense Evasion",
    },
    
    # Phase 3 Active Validation
    "mock_attack_vss_enum_succeeded": {
        "technique_id":   "T1490",
        "technique_name": "Inhibit System Recovery (Mock Attack)",
        "tactic":         "Impact",
    },
    "mock_attack_mass_rename_succeeded": {
        "technique_id":   "T1486",
        "technique_name": "Data Encrypted for Impact (Mock Attack)",
        "tactic":         "Impact",
    },
}


def get_mitre_mapping() -> dict[str, dict[str, str]]:
    """Return the full MITRE ATT&CK mapping dictionary."""
    return MITRE_MAPPING


def get_mitre_hits(flagged: dict[str, list[str]]) -> list[dict]:
    """
    Given the flagged parameters (grouped by phase), return a list of
    MITRE ATT&CK hits for each flagged parameter.
    """
    hits = []
    seen_techniques = set()
    for phase, params in flagged.items():
        for param in params:
            mitre = MITRE_MAPPING.get(param)
            if mitre:
                hit = {
                    "param_key":      param,
                    "phase":          phase,
                    "technique_id":   mitre["technique_id"],
                    "technique_name": mitre["technique_name"],
                    "tactic":         mitre["tactic"],
                }
                hits.append(hit)
                seen_techniques.add(mitre["technique_id"])
    return hits


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
        
        # New Fields
        "nla_disabled":            data.nla_disabled,
        "always_install_elevated": data.always_install_elevated,
        "wdigest_enabled":         data.wdigest_enabled,
        "laps_absent":             data.laps_absent,

        # Phase 2 Fields (invert since True in DB means RISKY)
        "vulnerable_driver_blocklist_enabled": not data.vulnerable_driver_blocklist_enabled if hasattr(data, 'vulnerable_driver_blocklist_enabled') else False,
        "hvci_enabled":            not data.hvci_enabled if hasattr(data, 'hvci_enabled') else False,
        "asr_rules_configured":    not data.asr_rules_configured if hasattr(data, 'asr_rules_configured') else False,

        # Phase 3 Active Validation
        # If the mock attack was NOT blocked (i.e. blocked is False), it is a RISKY state.
        # If it's None, it didn't run, so it's not a failure.
        "mock_attack_vss_enum_succeeded": getattr(data, 'mock_attack_vss_enum_blocked', None) is False,
        "mock_attack_mass_rename_succeeded": getattr(data, 'mock_attack_mass_rename_blocked', None) is False,
    }


def get_asset_criticality(asset_type: str) -> float:
    """Map asset type to a criticality multiplier."""
    t = asset_type.lower() if asset_type else "workstation"
    if t == "domain controller":
        return 1.6
    elif t == "server":
        return 1.3
    else:
        return 1.0


def score(data: CollectorData, asset_type: str = "Workstation") -> tuple[float, str, dict[str, list[str]], list[dict], float]:
    """
    Returns:
        risk_score   (0.0 – 100.0)
        risk_class   ("SAFE" | "LOW RISK" | "HIGH RISK" | "CRITICAL")
        flagged      dict mapping phase name to list of flagged parameter names
        mitre_hits   list of MITRE ATT&CK hits for flagged parameters
        criticality  the computed asset criticality multiplier
    """
    params = _translate(data)
    asset_criticality = get_asset_criticality(asset_type)
    
    total_risk = 0.0
    has_critical_failure = False
    flagged: dict[str, list[str]] = {phase: [] for phase in PHASES}

    # Max possible risk if everything fails
    max_possible_risk = sum(SEVERITY_WEIGHTS.get(k, 0) * LIKELIHOOD_WEIGHTS.get(k, 0) for k in SEVERITY_WEIGHTS) * asset_criticality

    for param, is_risky in params.items():
        if is_risky:
            severity = SEVERITY_WEIGHTS.get(param, 0.0)
            likelihood = LIKELIHOOD_WEIGHTS.get(param, 0.0)
            
            # Formula: Risk = Severity * Likelihood * AssetCriticality
            item_risk = severity * likelihood * asset_criticality
            total_risk += item_risk
            
            if severity == 5.0:
                has_critical_failure = True
            for phase, p_list in PHASES.items():
                if param in p_list:
                    flagged[phase].append(param)
                    break
    
    # Remove empty phases
    flagged = {k: v for k, v in flagged.items() if v}

    # Normalize to 0-100 scale
    normalized_score = (total_risk / max_possible_risk) * 100.0 if max_possible_risk > 0 else 0.0
    normalized_score = min(normalized_score, 100.0)

    if normalized_score < 20:
        risk_class = "SAFE"
    elif normalized_score < 50:
        risk_class = "LOW RISK"
    elif normalized_score < 80:
        risk_class = "HIGH RISK"
    else:
        risk_class = "CRITICAL"

    # Escalation rule for weight 5
    if has_critical_failure and risk_class in ["SAFE", "LOW RISK"]:
        risk_class = "HIGH RISK"

    # Generate MITRE ATT&CK hits for flagged parameters
    mitre_hits = get_mitre_hits(flagged)

    return round(normalized_score, 2), risk_class, flagged, mitre_hits, asset_criticality
