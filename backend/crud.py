"""
crud.py — Database read / write operations.
All functions take a SQLAlchemy Session as first argument.
"""

from sqlalchemy.orm import Session
from sqlalchemy import desc
from models import MachineRegistry, ConfigurationScan, RemediationCommand
from schemas import IngestRequest
from scoring import score
from datetime import datetime, timezone
from remediation_registry import get_command


def upsert_machine(db: Session, req: IngestRequest, ip: str,
                   risk_score: float, risk_class: str) -> MachineRegistry:
    """Create or update the machine registry row for this host."""
    machine = db.query(MachineRegistry).filter_by(hostname=req.host_id).first()
    if machine is None:
        machine = MachineRegistry(
            hostname=req.host_id,
            ip_address=ip,
            os_version=req.os,
        )
        db.add(machine)

    # Always refresh mutable fields
    machine.ip_address    = ip
    machine.os_version    = req.os
    machine.last_risk_score = risk_score
    machine.last_risk_class = risk_class
    db.flush()
    return machine


def create_scan(db: Session, req: IngestRequest, machine_id: int,
                ip: str, risk_score: float, risk_class: str,
                flagged: dict[str, list[str]], prev_score: float | None = None,
                is_anomaly: bool = False, anomaly_z_score: float | None = None) -> ConfigurationScan:
    """Insert one scan row from an IngestRequest."""
    d = req.data
    scan = ConfigurationScan(
        machine_id=machine_id,
        hostname=req.host_id,
        ip_address=ip,

        # Entry Vector
        smb_v1_enabled=d.smb_v1_enabled,
        rdp_enabled=d.rdp_open,                  # collector name → model name
        autorun_enabled=d.autorun_enabled,
        open_network_shares=d.open_network_shares,

        # Execution
        macro_execution_enabled=d.macro_execution_enabled,
        powershell_unrestricted=d.powershell_unrestricted,
        uac_disabled=d.uac_disabled,
        applocker_absent=d.applocker_absent,

        # Evasion/Persistence
        defender_disabled=d.defender_disabled,
        firewall_disabled=not d.firewall_on,      # invert firewall_on
        tamper_protection_off=d.tamper_protection_off,
        event_logging_disabled=d.event_logging_disabled,

        # Lateral Movement
        admin_shares_enabled=d.admin_shares_enabled,
        lsass_protection_off=d.lsass_protection_off,
        guest_account_active=d.guest_account_active,

        # Recovery Prevention
        vss_deleted=d.vss_deleted,
        backup_absent=not d.backup_configured,     # invert backup_configured
        bitlocker_off=d.bitlocker_off,

        risk_score=risk_score,
        risk_class=risk_class,
        flagged_parameters=",".join([item for sublist in flagged.values() for item in sublist]),
        is_anomaly=is_anomaly,
        anomaly_z_score=anomaly_z_score,
        prev_risk_score=prev_score,
    )
    db.add(scan)
    db.flush()
    return scan


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
    return db.query(MachineRegistry).order_by(
        desc(MachineRegistry.last_risk_score)
    ).all()


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


def get_anomaly_scans(db: Session, hostname: str, limit: int = 20) -> list[ConfigurationScan]:
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
