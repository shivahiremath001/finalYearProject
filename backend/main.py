"""
main.py — FastAPI application entry point.

Run with (single machine, dev):
    cd backend
    uvicorn main:app --reload --host 0.0.0.0 --port 8000

Run with multiple workers (recommended for 100+ agents):
    cd backend
    uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4

Run with HTTPS (self-signed cert, after generating with generate_cert.bat):
    cd backend
    uvicorn main:app --ssl-keyfile=certs\key.pem --ssl-certfile=certs\cert.pem --host 0.0.0.0 --port 8000

The collector.py / R3P_Agent.exe on any machine should point to:
    API_URL = "http://<SERVER_IP>:8000/ingest" (or https if using SSL)
"""

from fastapi import FastAPI, Depends, HTTPException, Request, Security
from fastapi.security import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import os
from dotenv import load_dotenv

import models
from database import engine, SessionLocal
from schemas import IngestRequest, ScanResponse, MachineOut, ScanOut
from scoring import score
import crud

load_dotenv()

# ── Create all tables on startup ─────────────────────────────────────────────
models.Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="R3P — Ransomware Readiness & Risk Profiler",
    description="Receives telemetry from Windows agents and scores security posture.",
    version="1.0.0",
)

# ── CORS: allow the Vite frontend (and any origin during dev) ─────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # tighten to your frontend URL in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── DB dependency ─────────────────────────────────────────────────────────────
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── API Key Auth ──────────────────────────────────────────────────────────────
API_KEY = os.environ.get("API_KEY", "R3P-DEMO-KEY")
api_key_header = APIKeyHeader(name="X-API-Key")

def get_api_key(api_key: str = Security(api_key_header)):
    if api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Could not validate credentials")
    return api_key


# ─────────────────────────────────────────────────────────────────────────────
# POST /ingest  ← This is what collector.py calls
# ─────────────────────────────────────────────────────────────────────────────
@app.post("/ingest", response_model=ScanResponse)
def ingest(req: IngestRequest, request: Request, db: Session = Depends(get_db), api_key: str = Security(get_api_key)):
    """
    Receives the telemetry payload from collector.py, scores the machine,
    persists it to the database, and returns the risk result.
    """
    # Prefer IP sent in payload; fall back to the HTTP client's address
    ip = req.ip or request.client.host or "unknown"

    # Score the machine
    risk_score, risk_class, flagged = score(req.data)

    # Upsert machine registry + insert scan row
    machine = crud.upsert_machine(db, req, ip, risk_score, risk_class)
    crud.create_scan(db, req, machine.id, ip, risk_score, risk_class, flagged)
    db.commit()

    print(
        f"[INGEST] {req.host_id} ({ip}) -> "
        f"score={risk_score} class={risk_class} flagged={flagged}"
    )

    return ScanResponse(
        message=f"Scan recorded. Risk class: {risk_class}",
        hostname=req.host_id,
        risk_score=risk_score,
        risk_class=risk_class,
        flagged=flagged,
    )


# ─────────────────────────────────────────────────────────────────────────────
# GET /machines  — list all registered machines
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/machines", response_model=list[MachineOut])
def list_machines(db: Session = Depends(get_db), api_key: str = Security(get_api_key)):
    return crud.get_all_machines(db)


# ─────────────────────────────────────────────────────────────────────────────
# GET /machines/{hostname}  — single machine detail
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/machines/{hostname}", response_model=MachineOut)
def get_machine(hostname: str, db: Session = Depends(get_db), api_key: str = Security(get_api_key)):
    machine = crud.get_machine(db, hostname)
    if not machine:
        raise HTTPException(status_code=404, detail="Machine not found")
    return machine


# ─────────────────────────────────────────────────────────────────────────────
# GET /machines/{hostname}/scans  — scan history
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/machines/{hostname}/scans", response_model=list[ScanOut])
def get_scans(hostname: str, limit: int = 20, db: Session = Depends(get_db), api_key: str = Security(get_api_key)):
    return crud.get_scans(db, hostname, limit)


# ─────────────────────────────────────────────────────────────────────────────
# GET /health  — quick liveness check
# ─────────────────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "service": "R3P Backend"}
