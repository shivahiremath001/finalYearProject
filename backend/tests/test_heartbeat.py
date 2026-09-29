import pytest
from datetime import datetime, timezone, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models import Base, MachineRegistry
from crud import mark_offline_machines

@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()

def test_mark_offline_machines(db_session):
    now = datetime.now(timezone.utc)
    
    # Machine 1: Online and active (seen 10s ago)
    m1 = MachineRegistry(hostname="HOST-1", ip_address="1.1.1.1", status="ONLINE", last_seen=now - timedelta(seconds=10))
    # Machine 2: Online but stale (seen 200s ago)
    m2 = MachineRegistry(hostname="HOST-2", ip_address="1.1.1.2", status="ONLINE", last_seen=now - timedelta(seconds=200))
    # Machine 3: Already offline (seen 300s ago)
    m3 = MachineRegistry(hostname="HOST-3", ip_address="1.1.1.3", status="OFFLINE", last_seen=now - timedelta(seconds=300))
    
    db_session.add_all([m1, m2, m3])
    db_session.commit()

    offline_hosts = mark_offline_machines(db_session, cutoff_seconds=150)
    
    # Only HOST-2 should be newly marked offline
    assert len(offline_hosts) == 1
    assert "HOST-2" in offline_hosts
    
    # Check DB statuses
    db_session.refresh(m1)
    db_session.refresh(m2)
    db_session.refresh(m3)
    
    assert m1.status == "ONLINE"
    assert m2.status == "OFFLINE"
    assert m3.status == "OFFLINE"
