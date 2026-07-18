from sqlalchemy import Column, Integer, String, Boolean, Float, DateTime
from sqlalchemy.sql import func
from database import Base


class MachineRegistry(Base):
    """
    Tracks every unique Windows endpoint that has ever sent a scan.
    One row per machine (identified by hostname).
    """
    __tablename__ = "machines"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String, unique=True, index=True, nullable=False)
    ip_address = Column(String, nullable=False)
    os_version = Column(String, nullable=True)
    first_seen = Column(DateTime(timezone=True), server_default=func.now())
    last_seen = Column(DateTime(timezone=True), onupdate=func.now(), server_default=func.now())
    last_risk_score = Column(Float, default=0.0)
    last_risk_class = Column(String, default="UNKNOWN")


class ConfigurationScan(Base):
    """
    Stores every scan result sent by a Windows agent.
    Each row = one full telemetry snapshot from one machine at one point in time.
    The 18 security parameters from the R3P report are stored as Boolean columns.
    """
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    machine_id = Column(Integer, nullable=False, index=True)
    hostname = Column(String, nullable=False)
    ip_address = Column(String, nullable=False)
    scanned_at = Column(DateTime(timezone=True), server_default=func.now())

    # ── ENTRY VECTOR PHASE ──────────────────────────────────────────────────
    smb_v1_enabled = Column(Boolean, default=False)          # SMBv1 enabled (WannaCry vector)
    rdp_enabled = Column(Boolean, default=False)             # RDP exposed
    autorun_enabled = Column(Boolean, default=False)         # USB AutoRun enabled
    open_network_shares = Column(Boolean, default=False)     # Unrestricted network shares

    # ── EXECUTION PHASE ─────────────────────────────────────────────────────
    macro_execution_enabled = Column(Boolean, default=False) # Office macros allowed
    powershell_unrestricted = Column(Boolean, default=False) # PowerShell execution unrestricted
    uac_disabled = Column(Boolean, default=False)            # User Account Control disabled
    applocker_absent = Column(Boolean, default=False)        # No application whitelisting

    # ── DEFENSE EVASION / PERSISTENCE PHASE ─────────────────────────────────
    defender_disabled = Column(Boolean, default=False)       # Windows Defender off
    firewall_disabled = Column(Boolean, default=False)       # Windows Firewall off
    tamper_protection_off = Column(Boolean, default=False)   # Defender tamper protection off
    event_logging_disabled = Column(Boolean, default=False)  # Event log collection off

    # ── LATERAL MOVEMENT / SPREAD PHASE ─────────────────────────────────────
    admin_shares_enabled = Column(Boolean, default=False)    # Default admin shares (C$, ADMIN$)
    lsass_protection_off = Column(Boolean, default=False)    # LSASS not protected (credential dump)
    guest_account_active = Column(Boolean, default=False)    # Guest account enabled

    # ── RECOVERY PREVENTION PHASE ────────────────────────────────────────────
    vss_deleted = Column(Boolean, default=False)             # Volume Shadow Copies absent
    backup_absent = Column(Boolean, default=False)           # No backup solution detected
    bitlocker_off = Column(Boolean, default=False)           # BitLocker encryption disabled

    # ── RISK RESULT ──────────────────────────────────────────────────────────
    risk_score = Column(Float, default=0.0)
    risk_class = Column(String, default="SAFE")              # SAFE | LOW RISK | HIGH RISK | CRITICAL
    flagged_parameters = Column(String, default="")          # Comma-separated list of flagged params
