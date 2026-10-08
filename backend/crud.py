"""
crud.py — Database read / write operations.
All functions take a SQLAlchemy Session as first argument.
"""

from sqlalchemy.orm import Session
from sqlalchemy import desc
import models
from models import MachineRegistry, ConfigurationScan, RemediationCommand
from schemas import IngestRequest
from scoring import score
from datetime import datetime, timezone
from remediation_registry import get_command


def find_machine(
    db: Session,
    hostname: str | None = None,
    mac_address: str | None = None,
    machine_guid: str | None = None,
) -> MachineRegistry | None:
    """
    Finds a machine by permanent identifiers in order of specificity:
    1. Machine GUID (Hardware UUID / OS MachineGuid)
    2. MAC Address (Physical NIC)
    3. Hostname
    """
    if machine_guid and machine_guid.strip().upper() not in ("UNKNOWN", "NONE", ""):
        m = db.query(MachineRegistry).filter(MachineRegistry.machine_guid == machine_guid.strip()).first()
        if m:
            return m

    if mac_address and mac_address.strip().upper() not in ("UNKNOWN", "00:00:00:00:00:00", ""):
        m = db.query(MachineRegistry).filter(MachineRegistry.mac_address == mac_address.strip().upper()).first()
        if m:
            return m

    if hostname and hostname.strip():
        m = db.query(MachineRegistry).filter(MachineRegistry.hostname == hostname.strip()).first()
        if m:
            return m

    return None


def upsert_machine(
    db: Session,
    req: IngestRequest,
    ip: str,
    risk_score: float,
    risk_class: str,
    asset_criticality: float = 1.0,
) -> MachineRegistry:
    """Create or update the machine registry row for this host using hardware GUID / MAC / hostname."""
    mac = req.mac_address.strip().upper() if req.mac_address else None
    guid = req.machine_guid.strip() if req.machine_guid else None

    machine = find_machine(db, hostname=req.host_id, mac_address=mac, machine_guid=guid)
    if machine is None:
        machine = MachineRegistry(
            hostname=req.host_id,
            ip_address=ip,
            mac_address=mac,
            machine_guid=guid,
            os_version=req.os,
        )
        db.add(machine)

    # Always refresh mutable fields & hardware identifiers
    machine.hostname = req.host_id
    machine.ip_address = ip
    if mac and mac not in ("UNKNOWN", "00:00:00:00:00:00"):
        machine.mac_address = mac
    if guid and guid not in ("UNKNOWN", "NONE"):
        machine.machine_guid = guid
    machine.os_version = req.os
    machine.last_risk_score = risk_score
    machine.last_risk_class = risk_class
    
    # Update active defense states
    d = req.data
    machine.active_defense_vss_enum = getattr(d, "mock_attack_vss_enum_blocked", None)
    machine.active_defense_mass_rename = getattr(d, "mock_attack_mass_rename_blocked", None)
    machine.active_defense_honeypot = getattr(d, "honeypot_triggered", False)
    
    machine.asset_criticality = asset_criticality
    machine.status = "ONLINE"
    db.flush()
    return machine


def create_scan(
    db: Session,
    req: IngestRequest,
    machine_id: int,
    ip: str,
    risk_score: float,
    risk_class: str,
    flagged: dict[str, list[str]],
    prev_score: float | None = None,
    is_anomaly: bool = False,
    anomaly_z_score: float | None = None,
    posture_diff: str | None = None,
) -> ConfigurationScan:
    """Insert one scan row from an IngestRequest."""
    d = req.data
    scan = ConfigurationScan(
        machine_id=machine_id,
        hostname=req.host_id,
        ip_address=ip,
        mac_address=req.mac_address.strip().upper() if req.mac_address else None,
        machine_guid=req.machine_guid.strip() if req.machine_guid else None,
        # Entry Vector
        smb_v1_enabled=d.smb_v1_enabled,
        rdp_enabled=d.rdp_open,  # collector name → model name
        autorun_enabled=d.autorun_enabled,
        open_network_shares=d.open_network_shares,
        # Execution
        macro_execution_enabled=d.macro_execution_enabled,
        powershell_unrestricted=d.powershell_unrestricted,
        uac_disabled=d.uac_disabled,
        applocker_absent=d.applocker_absent,
        # Evasion/Persistence
        defender_disabled=d.defender_disabled,
        firewall_disabled=not d.firewall_on,  # invert firewall_on
        tamper_protection_off=d.tamper_protection_off,
        event_logging_disabled=d.event_logging_disabled,
        # Lateral Movement
        admin_shares_enabled=d.admin_shares_enabled,
        lsass_protection_off=d.lsass_protection_off,
        guest_account_active=d.guest_account_active,
        # Recovery Prevention
        vss_deleted=d.vss_deleted,
        backup_absent=not d.backup_configured,  # invert backup_configured
        bitlocker_off=d.bitlocker_off,
        # New fields
        wdigest_enabled=d.wdigest_enabled,
        laps_absent=d.laps_absent,
        nla_disabled=d.nla_disabled,
        always_install_elevated=d.always_install_elevated,
        # Phase 2 BYOVD & EDR-Killer checks
        vulnerable_driver_blocklist_enabled=not getattr(
            d, "vulnerable_driver_blocklist_enabled", False
        ),
        hvci_enabled=not getattr(d, "hvci_enabled", False),
        asr_rules_configured=not getattr(d, "asr_rules_configured", False),
        # Phase 3 Active Validation (Mock Attacks)
        mock_attack_vss_enum_blocked=getattr(d, "mock_attack_vss_enum_blocked", None),
        mock_attack_mass_rename_blocked=getattr(
            d, "mock_attack_mass_rename_blocked", None
        ),
        honeypot_triggered=getattr(d, "honeypot_triggered", False),
        risk_score=risk_score,
        risk_class=risk_class,
        flagged_parameters=",".join(
            [item for sublist in flagged.values() for item in sublist]
        ),
        is_anomaly=is_anomaly,
        anomaly_z_score=anomaly_z_score,
        prev_risk_score=prev_score,
        posture_diff=posture_diff,
    )
    db.add(scan)
    db.flush()
    return scan


def get_latest_scan(db: Session, hostname: str) -> ConfigurationScan | None:
    """Return the most recent scan record for this host."""
    return (
        db.query(ConfigurationScan)
        .filter(ConfigurationScan.hostname == hostname)
        .order_by(desc(ConfigurationScan.scanned_at))
        .first()
    )


def get_previous_score(db: Session, hostname: str) -> float | None:
    """Return the most recent scan's risk_score for this host (for trend arrow)."""
    last = (
        db.query(ConfigurationScan)
        .filter_by(hostname=hostname)
        .order_by(desc(ConfigurationScan.scanned_at))
        .first()
    )
    return last.risk_score if last else None


def get_all_machines(db: Session) -> list[MachineRegistry]:
    return (
        db.query(MachineRegistry).order_by(desc(MachineRegistry.last_risk_score)).all()
    )


def get_machine(db: Session, hostname: str) -> MachineRegistry | None:
    return db.query(MachineRegistry).filter_by(hostname=hostname).first()


def get_scans(db: Session, hostname: str, limit: int = 20) -> list[ConfigurationScan]:
    return (
        db.query(ConfigurationScan)
        .filter_by(hostname=hostname)
        .order_by(desc(ConfigurationScan.scanned_at))
        .limit(limit)
        .all()
    )


def get_recent_scores(db: Session, hostname: str, limit: int = 10) -> list[float]:
    """Return the last N risk scores for this host (for anomaly z-score computation)."""
    rows = (
        db.query(ConfigurationScan.risk_score)
        .filter_by(hostname=hostname)
        .order_by(desc(ConfigurationScan.scanned_at))
        .limit(limit)
        .all()
    )
    return [r.risk_score for r in rows]


def update_anomaly_streak(db: Session, hostname: str, is_anomaly: bool):
    """Increment or reset the anomaly streak counter on the machine record."""
    machine = db.query(MachineRegistry).filter_by(hostname=hostname).first()
    if machine:
        if is_anomaly:
            machine.anomaly_streak = (machine.anomaly_streak or 0) + 1
        else:
            machine.anomaly_streak = 0
        db.flush()


def get_anomaly_scans(
    db: Session, hostname: str, limit: int = 20
) -> list[ConfigurationScan]:
    """Return scans flagged as anomalies for this host."""
    return (
        db.query(ConfigurationScan)
        .filter_by(hostname=hostname, is_anomaly=True)
        .order_by(desc(ConfigurationScan.scanned_at))
        .limit(limit)
        .all()
    )


# ─────────────────────────────────────────────────────────────────────────────
# Remediation Commands
# ─────────────────────────────────────────────────────────────────────────────


def queue_command(
    db: Session, hostname: str, command_key: str, issued_by: str = "admin"
) -> RemediationCommand:
    """Queue a new remediation command for a specific agent."""
    cmd_def = get_command(command_key)
    if cmd_def is None:
        raise ValueError(f"Unknown command key: '{command_key}'")

    cmd = RemediationCommand(
        hostname=hostname,
        command_key=command_key,
        status="pending",
        issued_by=issued_by,
        reboot_required=cmd_def.get("reboot_required", False),
    )
    db.add(cmd)
    db.flush()
    return cmd


def get_pending_commands(db: Session, hostname: str) -> list[RemediationCommand]:
    """Return all 'pending' commands for this agent (called by agent on poll)."""
    return (
        db.query(RemediationCommand)
        .filter_by(hostname=hostname, status="pending")
        .order_by(RemediationCommand.issued_at)
        .all()
    )


def ack_command(
    db: Session, cmd_id: int, status: str, output: str | None
) -> RemediationCommand | None:
    """Agent acknowledges completion of a command."""
    cmd = db.query(RemediationCommand).filter_by(id=cmd_id).first()
    if not cmd:
        return None
    cmd.status = status
    cmd.output = output
    cmd.completed_at = datetime.now(timezone.utc)
    db.flush()
    return cmd


def get_command_history(
    db: Session, hostname: str, limit: int = 50
) -> list[RemediationCommand]:
    """Return full command history for a machine (for admin history table)."""
    return (
        db.query(RemediationCommand)
        .filter_by(hostname=hostname)
        .order_by(desc(RemediationCommand.issued_at))
        .limit(limit)
        .all()
    )


def mark_executing(db: Session, cmd_id: int) -> RemediationCommand | None:
    """Mark a command as 'executing' when agent picks it up."""
    cmd = db.query(RemediationCommand).filter_by(id=cmd_id).first()
    if cmd:
        cmd.status = "executing"
        db.flush()
    return cmd


def has_pending_or_executing(db: Session, hostname: str, command_key: str) -> bool:
    """Check if this exact command is already pending/executing (prevent duplicates)."""
    return bool(
        db.query(RemediationCommand)
        .filter(
            RemediationCommand.hostname == hostname,
            RemediationCommand.command_key == command_key,
            RemediationCommand.status.in_(["pending", "executing"]),
        )
        .first()
    )


# ─────────────────────────────────────────────────────────────────────────────
# Policy Exceptions
# ─────────────────────────────────────────────────────────────────────────────


def get_policy_exceptions(
    db: Session, hostname: str = None
) -> list[models.PolicyException]:
    query = db.query(models.PolicyException)
    if hostname:
        query = query.filter(models.PolicyException.hostname == hostname)
    return query.all()


def create_policy_exception(
    db: Session, hostname: str, param_key: str, reason: str = None
) -> models.PolicyException:
    existing = (
        db.query(models.PolicyException)
        .filter_by(hostname=hostname, param_key=param_key)
        .first()
    )
    if existing:
        return existing

    exc = models.PolicyException(hostname=hostname, param_key=param_key, reason=reason)
    db.add(exc)
    db.commit()
    db.refresh(exc)
    return exc


def delete_policy_exception(db: Session, exc_id: int) -> models.PolicyException | None:
    exc = db.query(models.PolicyException).filter_by(id=exc_id).first()
    if exc:
        db.delete(exc)
        db.commit()
    return exc


def mark_offline_machines(db: Session, cutoff_seconds: int = 150) -> list[str]:
    """
    Marks machines as OFFLINE if they haven't been seen in cutoff_seconds.
    Returns a list of hostnames that were just marked offline.
    """
    cutoff = datetime.now(timezone.utc).timestamp() - cutoff_seconds
    offline_hosts = []
    machines = db.query(MachineRegistry).filter(MachineRegistry.status == "ONLINE").all()
    for m in machines:
        if m.last_seen:
            # SQLAlchemy DateTime with timezone=True needs care, but we assume it's UTC
            try:
                # If last_seen is naive, assume UTC
                if m.last_seen.tzinfo is None:
                    last_seen_ts = m.last_seen.replace(tzinfo=timezone.utc).timestamp()
                else:
                    last_seen_ts = m.last_seen.timestamp()
            except Exception:
                continue
            if last_seen_ts < cutoff:
                m.status = "OFFLINE"
                offline_hosts.append(m.hostname)
    if offline_hosts:
        db.commit()
    return offline_hosts


def seed_dummy_machine(db: Session):
    """Seed a dummy machine into the database for demonstration purposes."""
    dummy = db.query(MachineRegistry).filter_by(hostname="DUMMY-DEMO-01").first()
    if not dummy:
        dummy = MachineRegistry(
            hostname="DUMMY-DEMO-01",
            ip_address="10.0.0.99",
            mac_address="00:50:56:C0:00:08",
            machine_guid="a1b2c3d4-e5f6-7890-abcd-ef1234567890",
            os_version="Windows 11 Pro",
            last_risk_score=85.0,
            last_risk_class="CRITICAL",
        )
        db.add(dummy)
        db.commit()
        db.refresh(dummy)

        scan = ConfigurationScan(
            machine_id=dummy.id,
            hostname=dummy.hostname,
            ip_address=dummy.ip_address,
            mac_address=dummy.mac_address,
            machine_guid=dummy.machine_guid,
            smb_v1_enabled=True,
            rdp_enabled=True,
            autorun_enabled=True,
            wdigest_enabled=True,
            laps_absent=True,
            nla_disabled=False,
            always_install_elevated=False,
            risk_score=85.0,
            risk_class="CRITICAL",
            flagged_parameters="smb_v1_enabled,rdp_enabled,autorun_enabled,wdigest_enabled,laps_absent",
            is_anomaly=False,
        )
        db.add(scan)
        db.commit()


def prune_old_scans(db: Session, keep_days: int = 30):
    """
    Prune scan history older than `keep_days` to prevent unbounded database growth
    when continuously monitoring many agents.
    """
    from datetime import timedelta
    cutoff = datetime.now(timezone.utc) - timedelta(days=keep_days)
    # Delete older scans
    db.query(ConfigurationScan).filter(ConfigurationScan.scanned_at < cutoff).delete()
    db.commit()
