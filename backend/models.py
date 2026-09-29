from sqlalchemy import Column, Integer, String, Boolean, Float, DateTime, Text
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
    last_seen = Column(
        DateTime(timezone=True), onupdate=func.now(), server_default=func.now()
    )
    last_risk_score = Column(Float, default=0.0)
    last_risk_class = Column(String, default="UNKNOWN")
    asset_criticality = Column(Float, default=1.0)
    anomaly_streak = Column(Integer, default=0)  # Consecutive anomaly count
    status = Column(String, default="ONLINE")  # ONLINE | OFFLINE


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
    smb_v1_enabled = Column(Boolean, default=False)  # SMBv1 enabled (WannaCry vector)
    rdp_enabled = Column(Boolean, default=False)  # RDP exposed
    autorun_enabled = Column(Boolean, default=False)  # USB AutoRun enabled
    open_network_shares = Column(Boolean, default=False)  # Unrestricted network shares

    # ── EXECUTION PHASE ─────────────────────────────────────────────────────
    macro_execution_enabled = Column(Boolean, default=False)  # Office macros allowed
    powershell_unrestricted = Column(
        Boolean, default=False
    )  # PowerShell execution unrestricted
    uac_disabled = Column(Boolean, default=False)  # User Account Control disabled
    applocker_absent = Column(Boolean, default=False)  # No application whitelisting

    # ── DEFENSE EVASION / PERSISTENCE PHASE ─────────────────────────────────
    defender_disabled = Column(Boolean, default=False)  # Windows Defender off
    firewall_disabled = Column(Boolean, default=False)  # Windows Firewall off
    tamper_protection_off = Column(
        Boolean, default=False
    )  # Defender tamper protection off
    event_logging_disabled = Column(Boolean, default=False)  # Event log collection off

    # ── LATERAL MOVEMENT / SPREAD PHASE ─────────────────────────────────────
    admin_shares_enabled = Column(
        Boolean, default=False
    )  # Default admin shares (C$, ADMIN$)
    lsass_protection_off = Column(
        Boolean, default=False
    )  # LSASS not protected (credential dump)
    guest_account_active = Column(Boolean, default=False)  # Guest account enabled

    # ── RECOVERY PREVENTION PHASE ────────────────────────────────────────────
    vss_deleted = Column(Boolean, default=False)  # Volume Shadow Copies absent
    backup_absent = Column(Boolean, default=False)  # No backup solution detected
    bitlocker_off = Column(Boolean, default=False)  # BitLocker encryption disabled

    # ── NEW PARAMETERS ───────────────────────────────────────────────────────
    wdigest_enabled = Column(Boolean, default=False)
    laps_absent = Column(Boolean, default=False)
    nla_disabled = Column(Boolean, default=False)
    always_install_elevated = Column(Boolean, default=False)

    # ── PHASE 2 BYOVD & EDR-KILLER CHECKS ────────────────────────────────────
    vulnerable_driver_blocklist_enabled = Column(Boolean, default=False)
    hvci_enabled = Column(Boolean, default=False)
    asr_rules_configured = Column(Boolean, default=False)

    # ── PHASE 3 ACTIVE VALIDATION (MOCK ATTACKS) ──────────────────────────────
    mock_attack_vss_enum_blocked = Column(Boolean, nullable=True)
    mock_attack_mass_rename_blocked = Column(Boolean, nullable=True)

    # ── RISK RESULT ──────────────────────────────────────────────────────────
    risk_score = Column(Float, default=0.0)
    risk_class = Column(
        String, default="SAFE"
    )  # SAFE | LOW RISK | HIGH RISK | CRITICAL
    flagged_parameters = Column(
        String, default=""
    )  # Comma-separated list of flagged params
    posture_diff = Column(
        Text, nullable=True
    )  # JSON string of changed parameters since last scan
    is_anomaly = Column(Boolean, default=False)  # Z-score anomaly flag
    anomaly_z_score = Column(Float, nullable=True)  # Z-score value at scan time
    prev_risk_score = Column(
        Float, nullable=True
    )  # Previous scan score (for trend arrow)


class RemediationCommand(Base):
    """
    Tracks admin-issued remediation commands and their execution status.
    One row per command issued. The agent polls for 'pending' rows and
    updates status to 'executing' → 'done' | 'failed' via ACK endpoint.
    """

    __tablename__ = "remediation_commands"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String, nullable=False, index=True)
    command_key = Column(String, nullable=False)  # Must exist in remediation_registry
    status = Column(String, default="pending")  # pending|executing|done|failed
    issued_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
    output = Column(Text, nullable=True)  # stdout/stderr from agent
    issued_by = Column(String, default="admin")  # Admin username who issued command
    reboot_required = Column(Boolean, default=False)  # Whether fix needs reboot


class AdminUser(Base):
    """
    Admin users for the dashboard login page.
    Credentials are stored as PBKDF2-hashed passwords.
    """

    __tablename__ = "admin_users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_login = Column(DateTime(timezone=True), nullable=True)


class PolicyException(Base):
    """
    Security exceptions. If a machine has an exception for a parameter,
    it is ignored during scoring.
    """

    __tablename__ = "policy_exceptions"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String, nullable=False, index=True)
    param_key = Column(String, nullable=False)
    reason = Column(String, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
