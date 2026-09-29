import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import Base, ConfigurationScan, RemediationCommand
from anomaly import detect_anomaly

@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()

def seed_scans(db, hostname, scores):
    """Seed scan history for a machine"""
    for i, s in enumerate(scores):
        scan = ConfigurationScan(
            machine_id=1,
            hostname=hostname,
            ip_address="1.1.1.1",
            risk_score=s,
            scanned_at=datetime.now(timezone.utc) - timedelta(minutes=10 - i)
        )
        db.add(scan)
    db.commit()

def test_anomaly_small_change_not_flagged(db_session):
    # Identical history (mean 10.0, std 0.0)
    seed_scans(db_session, "HOST-1", [10.0] * 5)
    # Small change to 11.0 (difference 1.0, std_eff = 1.0 -> z = 1.0)
    res = detect_anomaly(db_session, "HOST-1", 11.0)
    assert not res.is_anomaly
    assert res.direction == "normal"

def test_anomaly_large_jump_flagged(db_session):
    # Identical history (mean 10.0, std 0.0)
    seed_scans(db_session, "HOST-2", [10.0] * 5)
    # Large change to 15.0 (diff 5.0, std_eff = 1.0 -> z = 5.0)
    res = detect_anomaly(db_session, "HOST-2", 15.0)
    assert res.is_anomaly
    assert res.direction == "spike"
    assert res.z_score == 5.0

def test_anomaly_post_remediation_drop_is_expected(db_session):
    # Mean 50.0
    seed_scans(db_session, "HOST-3", [50.0] * 5)
    
    # Add a recent successful remediation command (1 min ago)
    cmd = RemediationCommand(
        hostname="HOST-3",
        command_key="fix_something",
        status="done",
        completed_at=datetime.now(timezone.utc) - timedelta(minutes=1)
    )
    db_session.add(cmd)
    db_session.commit()

    # Drop to 10.0 -> z = -40.0
    res = detect_anomaly(db_session, "HOST-3", 10.0)
    assert not res.is_anomaly
    assert res.direction == "remediation_applied"

def test_anomaly_post_remediation_spike_is_flagged(db_session):
    # Mean 20.0
    seed_scans(db_session, "HOST-4", [20.0] * 5)
    
    # Add a recent successful remediation command (1 min ago)
    cmd = RemediationCommand(
        hostname="HOST-4",
        command_key="fix_something",
        status="done",
        completed_at=datetime.now(timezone.utc) - timedelta(minutes=1)
    )
    db_session.add(cmd)
    db_session.commit()

    # Spike to 60.0 -> z = 40.0
    res = detect_anomaly(db_session, "HOST-4", 60.0)
    assert res.is_anomaly
    assert res.direction == "spike"
