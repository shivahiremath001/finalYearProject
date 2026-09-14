"""
schemas.py — Pydantic models for request/response validation.

The /ingest endpoint accepts the exact payload that collector.py sends:
{
    "host_id": "PC-NAME",
    "os": "Windows 10",
    "timestamp": "2026-07-18T...",
    "data": {
        "rdp_open": true,
        "firewall_on": false,
        "patch_age_days": 14,
        "backup_configured": true
    }
}
All 18 model parameters are kept as Optional so the server stays
backward-compatible as the collector grows.
"""

from pydantic import BaseModel, Field
from typing import Optional, Any
from datetime import datetime


class CollectorData(BaseModel):
    """Inner 'data' block sent by collector.py"""

    # ── Fields the current collector already sends ───────────────────────────
    rdp_open: Optional[bool] = False
    firewall_on: Optional[bool] = True  # True = firewall IS on (safe)
    patch_age_days: Optional[int] = None
    backup_configured: Optional[bool] = True

    # ── Extended fields (future collector versions / manual agents) ──────────
    smb_v1_enabled: Optional[bool] = False
    autorun_enabled: Optional[bool] = False
    open_network_shares: Optional[bool] = False
    macro_execution_enabled: Optional[bool] = False
    powershell_unrestricted: Optional[bool] = False
    uac_disabled: Optional[bool] = False
    applocker_absent: Optional[bool] = False
    defender_disabled: Optional[bool] = False
    tamper_protection_off: Optional[bool] = False
    event_logging_disabled: Optional[bool] = False
    admin_shares_enabled: Optional[bool] = False
    lsass_protection_off: Optional[bool] = False
    guest_account_active: Optional[bool] = False
    vss_deleted: Optional[bool] = False
    bitlocker_off: Optional[bool] = False
    wdigest_enabled: Optional[bool] = False
    laps_absent: Optional[bool] = False
    nla_disabled: Optional[bool] = False
    always_install_elevated: Optional[bool] = False

    # ── Phase 2 BYOVD/EDR-Killer checks ──────────────────────────────────────
    vulnerable_driver_blocklist_enabled: Optional[bool] = False
    hvci_enabled: Optional[bool] = False
    asr_rules_configured: Optional[bool] = False

    # ── Phase 3 Active Validation (Mock Attacks) ─────────────────────────────
    mock_attack_vss_enum_blocked: Optional[bool] = None
    mock_attack_mass_rename_blocked: Optional[bool] = None


class IngestRequest(BaseModel):
    """Top-level payload that collector.py POSTs to /ingest"""

    host_id: str
    os: str
    asset_type: Optional[str] = "Workstation"
    timestamp: Optional[str] = None
    ip: Optional[str] = None  # auto-filled by server if not present
    data: CollectorData


class ScanResponse(BaseModel):
    """Response sent back to the collector after a successful ingest"""

    message: str
    hostname: str
    risk_score: float
    risk_class: str
    flagged: dict[str, list[str]]
    mitre_hits: list[dict] = []
    anomaly: Optional[dict] = None


class MitreHit(BaseModel):
    """One MITRE ATT&CK technique hit for a flagged parameter"""

    param_key: str
    phase: str
    technique_id: str
    technique_name: str
    tactic: str


class AnomalyInfo(BaseModel):
    """Anomaly detection result for a scan"""

    is_anomaly: bool = False
    z_score: Optional[float] = None
    rolling_mean: Optional[float] = None
    rolling_std: Optional[float] = None
    direction: str = "normal"  # "spike" | "drop" | "normal"
    scans_analyzed: int = 0


class MachineOut(BaseModel):
    """One row in the /machines list"""

    id: int
    hostname: str
    ip_address: str
    os_version: Optional[str]
    asset_criticality: Optional[float] = 1.0
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    last_risk_score: float
    last_risk_class: str

    model_config = {"from_attributes": True}


class ScanOut(BaseModel):
    """One scan record returned by /machines/{hostname}/scans"""

    id: int
    hostname: str
    ip_address: str
    scanned_at: Optional[datetime]
    risk_score: float
    risk_class: str
    flagged_parameters: str
    posture_diff: Optional[str] = None

    model_config = {"from_attributes": True}


# ─────────────────────────────────────────────────────────────────────────────
# Admin Auth
# ─────────────────────────────────────────────────────────────────────────────


class AdminLogin(BaseModel):
    """POST /admin/login body"""

    username: str
    password: str


class TokenOut(BaseModel):
    """Returned after successful admin login"""

    access_token: str
    token_type: str = "bearer"
    username: str


class AdminOut(BaseModel):
    """GET /admin/me response"""

    id: int
    username: str
    is_active: bool
    model_config = {"from_attributes": True}


# ─────────────────────────────────────────────────────────────────────────────
# Remediation Commands
# ─────────────────────────────────────────────────────────────────────────────


class IssueCommand(BaseModel):
    """POST /commands/{hostname} — admin queues a fix"""

    command_key: str


class CommandOut(BaseModel):
    """Returned to agent on GET /commands/{hostname}"""

    id: int
    command_key: str
    issued_at: Optional[datetime]
    status: str
    reboot_required: bool = False
    model_config = {"from_attributes": True}


class CommandAck(BaseModel):
    """POST /commands/{hostname}/{id}/ack — agent reports result"""

    status: str  # 'done' or 'failed'
    output: Optional[str] = None


class CommandHistoryOut(BaseModel):
    """Full command record for admin history view"""

    id: int
    hostname: str
    command_key: str
    status: str
    issued_at: Optional[datetime]
    completed_at: Optional[datetime]
    output: Optional[str]
    issued_by: str
    reboot_required: bool
    model_config = {"from_attributes": True}


class PolicyExceptionCreate(BaseModel):
    hostname: str
    param_key: str
    reason: Optional[str] = None


class PolicyExceptionOut(BaseModel):
    id: int
    hostname: str
    param_key: str
    reason: Optional[str] = None
    created_at: datetime
    model_config = {"from_attributes": True}


class RemediationCommandDef(BaseModel):
    """Definition of an available remediation command (from allowlist)"""

    key: str
    label: str
    description: str
    phase: str
    severity: str
    param_key: str
    reboot_required: bool
