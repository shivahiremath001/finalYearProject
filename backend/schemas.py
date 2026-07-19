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
from typing import Optional
from datetime import datetime


class CollectorData(BaseModel):
    """Inner 'data' block sent by collector.py"""

    # ── Fields the current collector already sends ───────────────────────────
    rdp_open:             Optional[bool] = False
    firewall_on:          Optional[bool] = True   # True = firewall IS on (safe)
    patch_age_days:       Optional[int]  = None
    backup_configured:    Optional[bool] = True

    # ── Extended fields (future collector versions / manual agents) ──────────
    smb_v1_enabled:          Optional[bool] = False
    autorun_enabled:          Optional[bool] = False
    open_network_shares:      Optional[bool] = False
    macro_execution_enabled:  Optional[bool] = False
    powershell_unrestricted:  Optional[bool] = False
    uac_disabled:             Optional[bool] = False
    applocker_absent:         Optional[bool] = False
    defender_disabled:        Optional[bool] = False
    tamper_protection_off:    Optional[bool] = False
    event_logging_disabled:   Optional[bool] = False
    admin_shares_enabled:     Optional[bool] = False
    lsass_protection_off:     Optional[bool] = False
    guest_account_active:     Optional[bool] = False
    vss_deleted:              Optional[bool] = False
    bitlocker_off:            Optional[bool] = False


class IngestRequest(BaseModel):
    """Top-level payload that collector.py POSTs to /ingest"""
    host_id:   str
    os:        str
    timestamp: Optional[str] = None
    ip:        Optional[str] = None   # auto-filled by server if not present
    data:      CollectorData


class ScanResponse(BaseModel):
    """Response sent back to the collector after a successful ingest"""
    message:    str
    hostname:   str
    risk_score: float
    risk_class: str
    flagged:    dict[str, list[str]]


class MachineOut(BaseModel):
    """One row in the /machines list"""
    id:              int
    hostname:        str
    ip_address:      str
    os_version:      Optional[str]
    first_seen:      Optional[datetime]
    last_seen:       Optional[datetime]
    last_risk_score: float
    last_risk_class: str

    model_config = {"from_attributes": True}


class ScanOut(BaseModel):
    """One scan record returned by /machines/{hostname}/scans"""
    id:               int
    hostname:         str
    ip_address:       str
    scanned_at:       Optional[datetime]
    risk_score:       float
    risk_class:       str
    flagged_parameters: str

    model_config = {"from_attributes": True}
