"""
crud.py — Database read / write operations.
All functions take a SQLAlchemy Session as first argument.
"""

from sqlalchemy.orm import Session
from sqlalchemy import desc
from models import MachineRegistry, ConfigurationScan
from schemas import IngestRequest
from scoring import score


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
                flagged: list[str]) -> ConfigurationScan:
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
        flagged_parameters=",".join(flagged),
    )
    db.add(scan)
    db.flush()
    return scan


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
