"""
main.py — FastAPI application entry point.

Run (dev):
    cd backend
    uvicorn main:app --reload --host 0.0.0.0 --port 8000

Run (production, multiple workers):
    uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4

Run (HTTPS with self-signed cert):
    uvicorn main:app --ssl-keyfile=certs\\key.pem --ssl-certfile=certs\\cert.pem --host 0.0.0.0 --port 8000

Endpoints
─────────
POST /ingest                          ← agent pushes telemetry (X-API-Key)
GET  /machines                        ← list all machines
GET  /machines/{hostname}             ← single machine detail
GET  /machines/{hostname}/scans       ← scan history
GET  /health                          ← liveness check

POST /admin/login                     ← admin username+password → JWT
GET  /admin/me                        ← current admin info (Bearer JWT)

POST /commands/{hostname}             ← admin queues a remediation fix (Bearer JWT)
GET  /commands/{hostname}             ← agent polls for pending commands (X-API-Key)
POST /commands/{hostname}/{cmd_id}/ack ← agent acks completion (X-API-Key)
GET  /commands/{hostname}/history     ← admin views command history (Bearer JWT)
GET  /remediation/available           ← list all available fix commands (Bearer JWT)

WS  /ws/live                          ← WebSocket: real-time scan events → dashboard
"""

from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    Request,
    Security,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.responses import FileResponse
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import datetime, timezone
import os
import json
import asyncio
from contextlib import asynccontextmanager
from typing import Set

# Load .env file
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    _env_path = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(_env_path):
        with open(_env_path) as _f:
            for _line in _f:
                _line = _line.strip()
                if _line and not _line.startswith("#") and "=" in _line:
                    _k, _, _v = _line.partition("=")
                    os.environ.setdefault(_k.strip(), _v.strip())

import models
from database import engine, SessionLocal, sync_db_schema
from schemas import (
    IngestRequest,
    ScanResponse,
    MachineOut,
    ScanOut,
    AdminLogin,
    TokenOut,
    AdminOut,
    IssueCommand,
    CommandOut,
    CommandAck,
    CommandHistoryOut,
    RemediationCommandDef,
    PolicyExceptionCreate,
    PolicyExceptionOut,
)
from scoring import score, get_mitre_mapping, get_mitre_hits, MITRE_MAPPING, PHASES
import crud
from auth import (
    verify_password,
    create_access_token,
    get_current_admin,
    ensure_default_admin,
    hash_password,
)
from remediation_registry import get_all_commands, get_command
from anomaly import detect_anomaly
from report_generator import generate_daily_report

# ── Create all tables & sync missing columns on startup ─────────────────────
models.Base.metadata.create_all(bind=engine)
sync_db_schema(engine, models.Base)


async def monitor_heartbeats():
    """Background task: checks every 30s for offline machines (>150s)."""
    while True:
        try:
            await asyncio.sleep(30)
            with SessionLocal() as db:
                offline_hosts = crud.mark_offline_machines(db, cutoff_seconds=150)
                for host in offline_hosts:
                    asyncio.create_task(manager.broadcast({
                        "type": "host_offline",
                        "hostname": host,
                        "message": f"Host {host} went offline."
                    }))
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"Error in heartbeat monitor: {e}")

# ── Lifespan (startup / shutdown logic) ──────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handles all startup and shutdown logic for the application."""
    # --- Startup ---
    db = SessionLocal()
    try:
        ensure_default_admin(db)
        crud.seed_dummy_machine(db)
    finally:
        db.close()
    
    # Start background tasks
    task = asyncio.create_task(monitor_heartbeats())
    
    yield
    # --- Shutdown (add cleanup here if needed in future) ---
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(
    title="R3P — Ransomware Readiness & Risk Profiler",
    description="Receives telemetry from Windows agents, scores security posture, and enables remote remediation.",
    version="2.0.0",
    lifespan=lifespan,
)

# ── CORS: allow the React frontend ───────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten to your frontend URL in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── WebSocket connection manager ──────────────────────────────────────────────
class LiveConnectionManager:
    """Manages active WebSocket connections from the admin dashboard."""

    def __init__(self):
        self.active: Set[WebSocket] = set()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.add(ws)

    def disconnect(self, ws: WebSocket):
        self.active.discard(ws)

    async def broadcast(self, data: dict):
        """Send a JSON event to all connected dashboard clients."""
        msg = json.dumps(data)
        dead = set()
        for ws in self.active:
            try:
                await ws.send_text(msg)
            except Exception:
                dead.add(ws)
        self.active -= dead


manager = LiveConnectionManager()


# ── DB dependency ─────────────────────────────────────────────────────────────
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── API Key Auth (for agents) ─────────────────────────────────────────────────
API_KEY = os.environ.get("API_KEY", "R3P-DEMO-KEY")
api_key_header = APIKeyHeader(name="X-API-Key")


def get_api_key(api_key: str = Security(api_key_header)):
    if api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Could not validate credentials")
    return api_key



# ─────────────────────────────────────────────────────────────────────────────
# AGENT ENDPOINTS (protected by X-API-Key)
# ─────────────────────────────────────────────────────────────────────────────


@app.post("/ingest", response_model=ScanResponse)
async def ingest(
    req: IngestRequest,
    request: Request,
    db: Session = Depends(get_db),
    api_key: str = Security(get_api_key),
):
    """
    Receives telemetry payload from collector.py, scores the machine,
    runs anomaly detection, persists to DB, and broadcasts to live
    dashboard via WebSocket.
    """
    ip = req.ip or request.client.host or "unknown"

    # Get previous score for trend arrow BEFORE upserting
    prev_score = crud.get_previous_score(db, req.host_id)
    prev_scan = crud.get_latest_scan(db, req.host_id)

    # Apply Policy Exceptions
    exceptions = crud.get_policy_exceptions(db, req.host_id)
    exc_keys = [e.param_key for e in exceptions]

    # Score the machine
    risk_score, risk_class, flagged, mitre_hits, asset_criticality, top_contributors = score(
        req.data, req.asset_type, excluded_params=set(exc_keys)
    )

    # Compute posture drift
    posture_diff = None
    if prev_scan:
        diffs = []
        old_flagged = [
            p.strip()
            for p in (prev_scan.flagged_parameters or "").split(",")
            if p.strip()
        ]
        new_flagged = []
        for p_list in flagged.values():
            new_flagged.extend(p_list)

        for p in new_flagged:
            if p not in old_flagged:
                diffs.append(f"+ {p}")
        for p in old_flagged:
            if p not in new_flagged:
                diffs.append(f"- {p}")
        if diffs:
            posture_diff = json.dumps(diffs)

    # Run anomaly detection (drift tracking)
    anomaly_result = detect_anomaly(db, req.host_id, risk_score)

    # Upsert machine registry + insert scan row (with anomaly data)
    machine = db.query(models.MachineRegistry).filter_by(hostname=req.host_id).first()
    was_offline = (machine is not None and machine.status == "OFFLINE")

    machine = crud.upsert_machine(
        db, req, ip, risk_score, risk_class, asset_criticality
    )
    crud.create_scan(
        db,
        req,
        machine.id,
        ip,
        risk_score,
        risk_class,
        flagged,
        prev_score,
        is_anomaly=anomaly_result.is_anomaly,
        anomaly_z_score=anomaly_result.z_score,
        posture_diff=posture_diff,
    )

    # Update anomaly streak on machine
    crud.update_anomaly_streak(db, req.host_id, anomaly_result.is_anomaly)
    db.commit()

    anomaly_flag = " [ANOMALY]" if anomaly_result.is_anomaly else ""
    print(
        f"[INGEST] {req.host_id} ({ip}) -> "
        f"score={risk_score} class={risk_class} "
        f"z={anomaly_result.z_score}{anomaly_flag} "
        f"trend={'UP' if prev_score and risk_score > prev_score else 'DOWN' if prev_score and risk_score < prev_score else '='}"
    )

    # Broadcast to WebSocket dashboard clients
    trend = None
    if prev_score is not None:
        if risk_score > prev_score:
            trend = "up"
        elif risk_score < prev_score:
            trend = "down"
        else:
            trend = "stable"

    anomaly_data = None
    if anomaly_result.z_score is not None:
        anomaly_data = {
            "is_anomaly": anomaly_result.is_anomaly,
            "z_score": anomaly_result.z_score,
            "rolling_mean": anomaly_result.rolling_mean,
            "rolling_std": anomaly_result.rolling_std,
            "direction": anomaly_result.direction,
            "scans_analyzed": anomaly_result.scans_analyzed,
        }

    await manager.broadcast(
        {
            "event": "scan",
            "hostname": req.host_id,
            "ip": ip,
            "os": req.os,
            "risk_score": risk_score,
            "risk_class": risk_class,
            "prev_risk_score": prev_score,
            "trend": trend,
            "flagged": flagged,
            "mitre_hits": mitre_hits,
            "anomaly": anomaly_data,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )

    if was_offline:
        await manager.broadcast({
            "type": "host_online",
            "hostname": req.host_id,
            "message": f"Host {req.host_id} came back online."
        })

    return ScanResponse(
        message=f"Scan recorded. Risk class: {risk_class}",
        hostname=req.host_id,
        risk_score=risk_score,
        risk_class=risk_class,
        flagged=flagged,
        mitre_hits=mitre_hits,
        anomaly=anomaly_data,
        top_contributors=top_contributors,
        policy_exceptions=[{"param_key": e.param_key, "reason": e.reason} for e in exceptions],
    )


@app.get("/commands/{hostname}", response_model=list[CommandOut])
def agent_poll_commands(
    hostname: str,
    db: Session = Depends(get_db),
    api_key: str = Security(get_api_key),
):
    """
    Agent polls this endpoint every 60 seconds to check for pending fix commands.
    Returns list of pending commands. Marks them as 'executing' immediately.
    """
    pending = crud.get_pending_commands(db, hostname)
    for cmd in pending:
        crud.mark_executing(db, cmd.id)
    db.commit()
    return pending


@app.post("/commands/{hostname}/{cmd_id}/ack")
def agent_ack_command(
    hostname: str,
    cmd_id: int,
    ack: CommandAck,
    db: Session = Depends(get_db),
    api_key: str = Security(get_api_key),
):
    """
    Agent reports success or failure of a remediation command.
    Status must be 'done' or 'failed'.
    """
    if ack.status not in ("done", "failed"):
        raise HTTPException(status_code=400, detail="Status must be 'done' or 'failed'")

    cmd = crud.ack_command(db, cmd_id, ack.status, ack.output)
    if not cmd:
        raise HTTPException(status_code=404, detail="Command not found")

    db.commit()
    print(
        f"[ACK] {hostname} cmd={cmd_id} status={ack.status} output={ack.output[:100] if ack.output else ''}"
    )
    return {"message": f"Command {cmd_id} acknowledged as {ack.status}"}


# ─────────────────────────────────────────────────────────────────────────────
# ADMIN AUTH ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────


@app.post("/admin/login", response_model=TokenOut)
def admin_login(login: AdminLogin, db: Session = Depends(get_db)):
    """Admin username + password → JWT access token."""
    admin = db.query(models.AdminUser).filter_by(username=login.username).first()
    if not admin or not verify_password(login.password, admin.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
        )
    if not admin.is_active:
        raise HTTPException(status_code=403, detail="Admin account is disabled")

    # Update last login
    admin.last_login = datetime.now(timezone.utc)
    db.commit()

    token = create_access_token({"sub": admin.username})
    return TokenOut(access_token=token, token_type="bearer", username=admin.username)


@app.get("/admin/me", response_model=AdminOut)
def admin_me(current_admin: models.AdminUser = Depends(get_current_admin)):
    """Returns the currently authenticated admin's info."""
    return current_admin


# ─────────────────────────────────────────────────────────────────────────────
# ADMIN DASHBOARD ENDPOINTS (protected by JWT Bearer token)
# ─────────────────────────────────────────────────────────────────────────────


@app.get("/machines", response_model=list[MachineOut])
def list_machines(
    db: Session = Depends(get_db),
    current_admin: models.AdminUser = Depends(get_current_admin),
):
    """List all registered machines, sorted by risk score descending."""
    return crud.get_all_machines(db)


@app.get("/machines/{hostname}", response_model=MachineOut)
def get_machine(
    hostname: str,
    db: Session = Depends(get_db),
    current_admin: models.AdminUser = Depends(get_current_admin),
):
    machine = crud.get_machine(db, hostname)
    if not machine:
        raise HTTPException(status_code=404, detail="Machine not found")
    return machine


@app.get("/machines/{hostname}/scans", response_model=list[ScanOut])
def get_scans(
    hostname: str,
    limit: int = 20,
    db: Session = Depends(get_db),
    current_admin: models.AdminUser = Depends(get_current_admin),
):
    return crud.get_scans(db, hostname, limit)


@app.get("/machines/{hostname}/detail")
def get_machine_detail(
    hostname: str,
    db: Session = Depends(get_db),
    current_admin: models.AdminUser = Depends(get_current_admin),
):
    """
    Returns rich detail for the admin dashboard machine panel:
    - Machine registry info
    - Last scan reconstructed flagged dict (grouped by kill-chain phase)
    - MITRE ATT&CK technique hits for flagged parameters
    - Anomaly detection data
    - Trend vs previous scan
    - Pending command count
    """
    machine = crud.get_machine(db, hostname)
    if not machine:
        raise HTTPException(status_code=404, detail="Machine not found")

    # Last two scans for trend
    scans = crud.get_scans(db, hostname, limit=2)
    last_scan = scans[0] if scans else None
    prev_scan = scans[1] if len(scans) > 1 else None

    # Reconstruct flagged dict from comma-separated stored string
    flagged: dict[str, list[str]] = {}
    if last_scan and last_scan.flagged_parameters:
        raw_params = [
            p.strip() for p in last_scan.flagged_parameters.split(",") if p.strip()
        ]
        for param in raw_params:
            for phase, phase_params in PHASES.items():
                if param in phase_params:
                    flagged.setdefault(phase, []).append(param)
                    break

    # Generate MITRE hits from flagged params
    mitre_hits = get_mitre_hits(flagged)

    # Trend
    trend = None
    if last_scan and prev_scan:
        if last_scan.risk_score > prev_scan.risk_score:
            trend = "up"
        elif last_scan.risk_score < prev_scan.risk_score:
            trend = "down"
        else:
            trend = "stable"

    # Anomaly data from last scan
    anomaly_data = None
    if last_scan and last_scan.anomaly_z_score is not None:
        anomaly_data = {
            "is_anomaly": last_scan.is_anomaly,
            "z_score": last_scan.anomaly_z_score,
        }

    # Recent score history for timeline chart (last 20 scans, oldest first)
    recent_scans = crud.get_scans(db, hostname, limit=20)
    score_history = [
        {
            "score": s.risk_score,
            "risk_class": s.risk_class,
            "is_anomaly": s.is_anomaly or False,
            "scanned_at": s.scanned_at.isoformat() if s.scanned_at else None,
        }
        for s in reversed(recent_scans)  # oldest first for chart
    ]

    # Pending commands
    pending_cmds = crud.get_pending_commands(db, hostname)

    return {
        "hostname": machine.hostname,
        "ip_address": machine.ip_address,
        "os_version": machine.os_version,
        "first_seen": machine.first_seen,
        "last_seen": machine.last_seen,
        "risk_score": last_scan.risk_score if last_scan else 0,
        "risk_class": last_scan.risk_class if last_scan else machine.last_risk_class,
        "prev_risk_score": prev_scan.risk_score if prev_scan else None,
        "trend": trend,
        "flagged": flagged,
        "mitre_hits": mitre_hits,
        "anomaly": anomaly_data,
        "anomaly_streak": machine.anomaly_streak or 0,
        "score_history": score_history,
        "scanned_at": last_scan.scanned_at if last_scan else None,
        "pending_commands": len(pending_cmds),
    }


@app.post("/commands/{hostname}", response_model=CommandHistoryOut)
def admin_issue_command(
    hostname: str,
    body: IssueCommand,
    db: Session = Depends(get_db),
    current_admin: models.AdminUser = Depends(get_current_admin),
):
    """
    Admin queues a remediation command for a specific agent.
    Rejects if the same command is already pending/executing (deduplication).
    """
    # Validate command key exists in allowlist
    if not get_command(body.command_key):
        raise HTTPException(
            status_code=400,
            detail=f"Unknown command key '{body.command_key}'. Check /remediation/available.",
        )

    # Machine must exist
    machine = crud.get_machine(db, hostname)
    if not machine:
        raise HTTPException(status_code=404, detail=f"Machine '{hostname}' not found")

    # Deduplication: block if already pending/executing
    if crud.has_pending_or_executing(db, hostname, body.command_key):
        raise HTTPException(
            status_code=409,
            detail=f"Command '{body.command_key}' is already pending or executing on {hostname}",
        )

    cmd = crud.queue_command(
        db, hostname, body.command_key, issued_by=current_admin.username
    )
    db.commit()

    print(
        f"[CMD] Admin '{current_admin.username}' queued '{body.command_key}' → {hostname}"
    )
    return cmd


@app.get("/commands/{hostname}/history", response_model=list[CommandHistoryOut])
def get_command_history(
    hostname: str,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_admin: models.AdminUser = Depends(get_current_admin),
):
    """Return the full remediation command history for a machine."""
    return crud.get_command_history(db, hostname, limit)


@app.get("/remediation/available", response_model=list[RemediationCommandDef])
def list_available_remediations(
    current_admin: models.AdminUser = Depends(get_current_admin),
):
    """Return all available remediation commands from the allowlist."""
    cmds = get_all_commands()
    return [
        RemediationCommandDef(
            key=k,
            label=v["label"],
            description=v["description"],
            phase=v["phase"],
            severity=v["severity"],
            param_key=v["param_key"],
            reboot_required=v.get("reboot_required", False),
        )
        for k, v in cmds.items()
    ]


@app.get("/reports/daily/download")
def download_daily_report(
    db: Session = Depends(get_db),
    current_admin: models.AdminUser = Depends(get_current_admin),
):
    """Generates and returns the daily report PDF."""
    try:
        filepath = generate_daily_report(db)
        return FileResponse(
            path=filepath,
            filename=os.path.basename(filepath),
            media_type="application/pdf"
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {e}")


@app.get("/reports/dummy/download")
def download_dummy_report(
    current_admin: models.AdminUser = Depends(get_current_admin),
):
    """Returns the latest pre-generated dummy PDF report for structure preview."""
    reports_dir = os.path.join(os.path.dirname(__file__), "reports")
    dummy_files = sorted(
        [f for f in os.listdir(reports_dir) if f.startswith("dummy_report")],
        reverse=True,
    )
    if not dummy_files:
        raise HTTPException(status_code=404, detail="No dummy report found. Run generate_dummy_report.py first.")
    filepath = os.path.join(reports_dir, dummy_files[0])
    return FileResponse(
        path=filepath,
        filename="R3P_Dummy_Report_Preview.pdf",
        media_type="application/pdf"
    )


@app.get("/mitre/mapping")
def get_mitre_mapping_endpoint(
    current_admin: models.AdminUser = Depends(get_current_admin),
):
    """Return the full MITRE ATT&CK mapping table."""
    return get_mitre_mapping()


@app.get("/machines/{hostname}/anomalies")
def get_anomaly_history(
    hostname: str,
    limit: int = 20,
    db: Session = Depends(get_db),
    current_admin: models.AdminUser = Depends(get_current_admin),
):
    """Return scans flagged as anomalies for this machine."""
    anomaly_scans = crud.get_anomaly_scans(db, hostname, limit)
    return [
        {
            "id": s.id,
            "risk_score": s.risk_score,
            "risk_class": s.risk_class,
            "z_score": s.anomaly_z_score,
            "scanned_at": s.scanned_at,
        }
        for s in anomaly_scans
    ]


# ─────────────────────────────────────────────────────────────────────────────
# WEBSOCKET — Real-time dashboard feed
# ─────────────────────────────────────────────────────────────────────────────


@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
    """
    Dashboard connects here to receive real-time scan events.
    No auth on the WebSocket itself — dashboard must validate the JWT
    before connecting (sent as a query param: /ws/live?token=<jwt>).
    """
    token = websocket.query_params.get("token", "")
    from auth import decode_token

    payload = decode_token(token)
    if not payload:
        await websocket.close(code=4001)
        return

    await manager.connect(websocket)
    try:
        # Send a welcome event with current machine count
        db = SessionLocal()
        try:
            machines = crud.get_all_machines(db)
            await websocket.send_text(
                json.dumps(
                    {
                        "event": "connected",
                        "machine_count": len(machines),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )
            )
        finally:
            db.close()

        # Keep connection alive; client just listens for broadcasts
        while True:
            await asyncio.sleep(30)
            await websocket.send_text(json.dumps({"event": "ping"}))
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# ─────────────────────────────────────────────────────────────────────────────
# HEALTH
# ─────────────────────────────────────────────────────────────────────────────


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "R3P Backend v2",
        "ws_clients": len(manager.active),
    }


# ─────────────────────────────────────────────────────────────────────────────
# ENTERPRISE FEATURES: Policies, Global Remediation, Analytics
# ─────────────────────────────────────────────────────────────────────────────


@app.get("/policies", response_model=list[PolicyExceptionOut])
def get_policies(
    db: Session = Depends(get_db), admin: str = Depends(get_current_admin)
):
    return crud.get_policy_exceptions(db)


@app.post("/policies", response_model=PolicyExceptionOut)
def create_policy(
    policy: PolicyExceptionCreate,
    db: Session = Depends(get_db),
    admin: str = Depends(get_current_admin),
):
    return crud.create_policy_exception(
        db, policy.hostname, policy.param_key, policy.reason
    )


@app.delete("/policies/{exc_id}")
def delete_policy(
    exc_id: int, db: Session = Depends(get_db), admin: str = Depends(get_current_admin)
):
    crud.delete_policy_exception(db, exc_id)
    return {"status": "ok"}


@app.post("/commands/global")
def global_remediation(
    req: IssueCommand,
    db: Session = Depends(get_db),
    admin: str = Depends(get_current_admin),
):
    """Finds all machines that currently have this issue and queues a fix for all."""
    # Find all machines where their *latest* scan has this parameter set to True
    from sqlalchemy import desc

    machines = db.query(models.MachineRegistry).all()
    queued_count = 0
    for m in machines:
        latest = (
            db.query(models.ConfigurationScan)
            .filter_by(hostname=m.hostname)
            .order_by(desc(models.ConfigurationScan.scanned_at))
            .first()
        )
        if latest and getattr(latest, req.command_key, False):
            # It has the vulnerability
            if not crud.has_pending_or_executing(db, m.hostname, req.command_key):
                crud.queue_command(db, m.hostname, req.command_key, issued_by=admin)
                queued_count += 1
    db.commit()
    return {"status": "queued", "count": queued_count}


@app.get("/analytics/history")
def get_analytics_history(
    db: Session = Depends(get_db), admin: str = Depends(get_current_admin)
):
    """Returns the fleet average risk score by day."""
    from sqlalchemy.sql import func

    # Group by date part of scanned_at and avg risk score
    # Note: SQLite uses strftime
    if db.bind.dialect.name == "sqlite":
        date_expr = func.strftime("%Y-%m-%d", models.ConfigurationScan.scanned_at)
    else:
        date_expr = func.date(models.ConfigurationScan.scanned_at)

    results = (
        db.query(
            date_expr.label("date"),
            func.avg(models.ConfigurationScan.risk_score).label("avg_risk"),
        )
        .group_by(date_expr)
        .order_by(date_expr)
        .all()
    )

    history = [{"date": str(r.date), "avgRisk": round(r.avg_risk, 2)} for r in results]
    return {"history": history}
